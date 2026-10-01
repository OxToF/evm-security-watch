// EVM Watchdog — scan backend. Paid in USDG on Robinhood Chain.
//
// Web flow:   POST /scan {repo,email}        -> job + a unique USDG amount to pay
//             POST /pay/verify {jobId,txHash} -> checks the transfer on-chain, queues
//             the scan, emails the report.
// Agent flow: POST /agent/scan {repo}        -> HTTP 402 with x402-style requirements
//             POST /agent/scan {jobId,txHash} -> same check, then the agent polls
//             GET /agent/jobs/:id with the bearer token it got at quote time.
//
// x402 rail:  the same 402 carries a PAYMENT-REQUIRED header for USDC on Base.
//             A standard x402 client resends with PAYMENT-SIGNATURE; a facilitator
//             settles it and the paid answer is the job (see settleX402).
//
// A quote's amount is unique among open quotes: EVM transfers carry no memo, so the
// amount is what ties a public payment to one job (see verify.mjs).
// Zero runtime deps: Node http + fetch only.
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runScan, parseGithubUrl, WATCHDOG_LOGO, fixMailto, scanDependencies, scanDependenciesBatch, parseLockfileText } from "../bin/scan.mjs";
import { Store } from "./store.mjs";
import { Queue } from "./queue.mjs";
import { sendReport } from "./email.mjs";
import { verifyUsdgPayment, USDG, toBase, formatUnits } from "./verify.mjs";
import { Facilitator, BASE_MAINNET, BASE_USDC, encodeHeader, decodeHeader, bazaarExtension } from "./x402.mjs";
import { PayAIAuth } from "./payai-auth.mjs";
import { inspectContract, isAddress } from "./contract.mjs";
import { Watcher, checkWebhookUrl, newSecret, contractSnapshot, diffContract, lockfileSnapshot, diffLockfile } from "./watch.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const PRICE_USD = Number(process.env.SCAN_PRICE_USD || 69); // web: a human, a branded report by email
// Agents buy per request, at volume: both prices sit under the $1 per-payment cap
// x402 clients ship with, so an agent on default settings can pay without a human.
// A PayAI settlement costs about $0.0023 on Base, so a cent still clears it.
const AGENT_SCAN_PRICE_USD = Number(process.env.AGENT_SCAN_PRICE_USD || 0.5);
const CHECK_PRICE_USD = Number(process.env.CHECK_PRICE_USD || 0.01);
const CHECK_MAX_PACKAGES = 100;
// A whole lockfile instead of a list: one OSV batch call, so the size barely costs us.
const LOCKFILE_MAX_BYTES = 2_000_000;
const LOCKFILE_MAX_PACKAGES = 5000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "*";
const MERCHANT_WALLET = process.env.MERCHANT_WALLET ? process.env.MERCHANT_WALLET.toLowerCase() : null;
const RPC_URL = process.env.EVM_RPC_URL || "https://rpc.mainnet.chain.robinhood.com";
const QUOTE_TTL_MS = Number(process.env.QUOTE_TTL_HOURS || 24) * 3600_000;
// Unique part of a quote, in base units: up to 0.099999 USDG on top of the price.
const AMOUNT_SPREAD = 100_000;
// On a $0.50 agent quote a 0.1 spread would be a fifth of the price: at most 0.009999.
const AGENT_AMOUNT_SPREAD = 10_000;
const JOBS_FILE = process.env.JOBS_FILE || join(__dirname, "data", "jobs.json");
const REPORTS_DIR = process.env.REPORTS_DIR || join(dirname(JOBS_FILE), "reports");
const PUBLIC_BASE = (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const EXPLORER = "https://robinhoodchain.blockscout.com";
// x402 on Base. "off" leaves only the USDG rail.
const FACILITATOR_URL = process.env.FACILITATOR_URL || "https://facilitator.payai.network";
const BASE_RPC_URL = process.env.BASE_RPC_URL || "https://mainnet.base.org";
const CONTRACT_PRICE_USD = Number(process.env.CONTRACT_PRICE_USD || 0.05);
const CONTRACT_CHAINS = { base: BASE_RPC_URL, robinhood: RPC_URL };
// A watch is bought once for a fixed period, under the $1 default cap of x402 clients.
const WATCH_PRICE_USD = Number(process.env.WATCH_PRICE_USD || 0.9);
const WATCH_DAYS = Number(process.env.WATCH_DAYS || 30);
const WATCH_INTERVAL_MS = Number(process.env.WATCH_INTERVAL_MS || 60 * 60 * 1000);
const WATCH_TICK_MS = Number(process.env.WATCH_TICK_MS || 60 * 1000);
const WATCH_ALLOW_PRIVATE = process.env.WATCH_ALLOW_PRIVATE_WEBHOOKS === "1"; // tests only
const SUPPORT = process.env.SUPPORT_EMAIL || null;
const CONTACT = SUPPORT || "solanawatchdog@proton.me";

if (MERCHANT_WALLET && !/^0x[0-9a-f]{40}$/.test(MERCHANT_WALLET)) throw new Error("MERCHANT_WALLET is not an 0x address");

const store = new Store(JOBS_FILE);
const watches = new Store(process.env.WATCHES_FILE || join(dirname(JOBS_FILE), "watches.json"));
// A bad key is never sent: PayAI refuses every payment that carries one. It is not
// fatal either (on 2026-10-01 a masked secret took both apps down at boot): the
// server stays up on the public lane and says so at boot and in /health.
let payaiAuth = null, payaiAuthError = null;
try { payaiAuth = PayAIAuth.fromEnv(); }
catch (e) { payaiAuthError = e.message; }
const facilitator = FACILITATOR_URL === "off" ? null : new Facilitator({ url: FACILITATOR_URL, auth: payaiAuth });
// ERC-8004 identity, once registered on Base: the agentId minted by register().
const ERC8004_REGISTRY = "eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";
const ERC8004_AGENT_ID = process.env.ERC8004_AGENT_ID ? Number(process.env.ERC8004_AGENT_ID) : null;
const queue = new Queue();

// --- tiny per-IP rate limit (protects the quote endpoints) ---
const hits = new Map();
function rateLimited(ip, max = 20, windowMs = 60000) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > max;
}

function send(res, code, body, extraHeaders = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(code, {
    "content-type": typeof body === "string" ? "text/plain" : "application/json",
    "access-control-allow-origin": ALLOW_ORIGIN,
    "access-control-allow-methods": "POST, GET, DELETE, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, payment-signature",
    "access-control-expose-headers": "payment-required, payment-response",
    ...extraHeaders,
  });
  res.end(payload);
}

function readBody(req, max = 1e5) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > max) req.destroy(); });
    req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new Error("bad json")); } });
    req.on("error", reject);
  });
}

const validEmail = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e || "");
const hashToken = (t) => createHash("sha256").update(String(t)).digest("hex");

function summarize(result) {
  const bk = result.deps.buckets, cov = result.deps.coverage;
  return {
    repo: `${result.meta.owner}/${result.meta.repo}`,
    date: result.meta.date,
    counts: {
      onchainAdvisories: bk.onchain.length,
      toolchainAdvisories: bk.toolchain.length,
      dependencyVersionsChecked: cov.checked,
      dependenciesNotChecked: cov.unresolved.length,
      codeLeads: [...result.source.byClass.values()].reduce((s, e) => s + e.total, 0),
    },
    onchainAdvisories: bk.onchain,
    toolchainAdvisories: bk.toolchain,
    notChecked: cov.unresolved.map(({ path, url, sha, reason, production }) => ({ path, url, sha, reason, production })),
    noExternalImports: cov.noExternalImports,
    hygiene: result.hygiene,
    codeLeads: [...result.source.byClass.values()].map((e) => ({ class: e.cls, label: e.label, total: e.total, hits: e.hits })),
    disclaimer: "A dependency + known-class scan, not an audit. It does not certify the absence of bugs.",
  };
}

// --- the actual work: run a paid scan, keep/email the report ---
async function runJob(jobId) {
  const job = store.get(jobId);
  if (!job) return;
  store.update(jobId, { status: "running" });
  let result = null;
  try {
    const out = mkdtempSync(join(tmpdir(), "evmw-job-"));
    const cta = { contact: CONTACT, ref: jobId };
    result = await runScan({ repoUrl: job.repo, out, log: () => {}, cta });
    const html = readFileSync(result.htmlPath, "utf8");
    const md = readFileSync(result.mdPath, "utf8");
    const sum = summarize(result);
    // Every report is kept, so the email can link to it: mail clients show an
    // attached .html as source code, not as the branded page.
    mkdirSync(REPORTS_DIR, { recursive: true });
    writeFileSync(join(REPORTS_DIR, `${jobId}.html`), html);
    writeFileSync(join(REPORTS_DIR, `${jobId}.md`), md);
    writeFileSync(join(REPORTS_DIR, `${jobId}.json`), JSON.stringify(sum, null, 2) + "\n");
    const viewToken = randomBytes(24).toString("base64url");
    store.update(jobId, { viewTokenHash: hashToken(viewToken) });
    const viewUrl = `${PUBLIC_BASE}/r/${jobId}/${viewToken}`;
    const fixUrl = fixMailto(cta, result.meta, `Fix request: ${sum.repo}`, [`On-chain advisories: ${sum.counts.onchainAdvisories}`, `Code leads: ${sum.counts.codeLeads}`]);
    const c = sum.counts;
    const headline = sum.noExternalImports
      ? "Your production contracts import no external library."
      : c.dependencyVersionsChecked
        ? `${c.onchainAdvisories} advisories on your on-chain surface (libraries your deployed contracts import)`
        : "Dependencies NOT checked: no version could be resolved (see the report).";
    const top = sum.onchainAdvisories.slice(0, 3).map((a) => `- [${a.severity}] ${a.id} — ${a.summary}`).join("\n");
    if (job.email) await sendReport({
      to: job.email,
      subject: `Your EVM security scan — ${sum.repo}`,
      text: `Scan complete for ${job.repo}.\n\n${headline}\n${c.toolchainAdvisories} more in toolchain/test packages, ${c.dependenciesNotChecked} dependencies not checked, ${c.codeLeads} code leads.\n\n${top}\n\nView your report: ${viewUrl}\nWant the findings fixed? Write to ${CONTACT} with reference ${jobId}.\n\nThe report is also attached. A scan, not an audit.`,
      html: `<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:560px;margin:auto;background:#fff;border-radius:14px;overflow:hidden;border:1px solid #eaecf3">
<div style="background:#160b2e;padding:18px 22px;border-bottom:3px solid #14F195">
<span style="color:#fff;font-weight:800;letter-spacing:.5px;font-size:16px">EVM <span style="color:#14F195">WATCHDOG</span></span>
<div style="color:#a9b0cf;font-size:12px;margin-top:3px">Dependency &amp; known-class security scan</div></div>
<div style="padding:22px">
<p style="margin:0 0 12px;font-size:15px;color:#1c2030">Scan complete for <b>${sum.repo}</b>.</p>
<p style="margin:0 0 14px;color:#1c2030">${headline}<br><b>${c.toolchainAdvisories}</b> in toolchain / test packages &middot; <b>${c.dependenciesNotChecked}</b> dependencies not checked &middot; <b>${c.codeLeads}</b> code leads</p>
${top ? `<div style="background:#f7f8fc;border:1px solid #eaecf3;border-radius:10px;padding:12px 14px;font-size:13px;color:#333;white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace">${top.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>` : ""}
<table role="presentation" cellspacing="0" cellpadding="0" style="margin:18px 0 0"><tr>
<td style="padding:0 8px 8px 0"><a href="${viewUrl}" style="display:inline-block;background:#6d3bd6;color:#ffffff;font-weight:700;text-decoration:none;border-radius:10px;padding:12px 18px">View your report</a></td>
<td style="padding:0 0 8px 0"><a href="${fixUrl}" style="display:inline-block;background:#ffffff;color:#6d3bd6;font-weight:700;text-decoration:none;border-radius:10px;padding:11px 17px;border:1px solid #6d3bd6">Get the findings fixed</a></td>
</tr></table>
<p style="margin:10px 0 0;color:#5b6178;font-size:13px">The link is private to you. The report is also attached (open the <b>.html</b> in a browser).</p>
<p style="margin:14px 0 0;color:#8189a3;font-size:12px">A hygiene + known-class scan, not an audit. It does not certify the absence of bugs.</p></div></div>`,
      attachments: [
        { filename: `${result.meta.owner}-${result.meta.repo}-scan.html`, content: Buffer.from(html).toString("base64") },
        { filename: `${result.meta.owner}-${result.meta.repo}-scan.md`, content: Buffer.from(md).toString("base64") },
      ],
    });
    store.update(jobId, { status: "done", onchainAdvisories: c.onchainAdvisories, versionsChecked: c.dependencyVersionsChecked, notChecked: c.dependenciesNotChecked, codeLeads: c.codeLeads, deliveredAt: new Date().toISOString() });
  } catch (e) {
    store.update(jobId, { status: "error", error: String(e.message).slice(0, 300) });
    console.error(`[job ${jobId}] failed:`, e.message);
  } finally {
    if (result && result.cleanup) rmSync(result.cleanup, { recursive: true, force: true });
  }
}

// --- quotes and payment -------------------------------------------------------

function createQuote(fields, price = PRICE_USD, spread = AMOUNT_SPREAD) {
  const amountBase = store.uniqueAmount(toBase(price), spread, QUOTE_TTL_MS);
  return store.create({ ...fields, priceUsd: price, amountBase, expiresAt: new Date(Date.now() + QUOTE_TTL_MS).toISOString() });
}

function paymentTerms(job) {
  return {
    network: "Robinhood Chain",
    chainId: USDG.chainId,
    token: USDG.address,
    symbol: USDG.symbol,
    decimals: USDG.decimals,
    payTo: MERCHANT_WALLET,
    amount: formatUnits(job.amountBase),
    amountBase: job.amountBase,
    expiresAt: job.expiresAt,
    note: `Send EXACTLY ${formatUnits(job.amountBase)} USDG (token ${USDG.address}) to ${MERCHANT_WALLET}. The amount is unique to this quote; any other amount is not matched to it.`,
  };
}

// Verify a tx for a job and queue the scan. Returns [status, body].
async function claimPayment(job, txHash) {
  if (typeof txHash !== "string" || !txHash) return [400, { error: "txHash required" }];
  const h = txHash.toLowerCase();
  if (job.status !== "pending_payment") return [409, { error: `job already ${job.status}` }];
  if (Date.now() > Date.parse(job.expiresAt)) return [410, { error: `quote expired; if you already paid, ${SUPPORT ? `write to ${SUPPORT}` : "contact support"} with the jobId and txHash` }];
  if (store.findByPayment(h)) return [409, { error: "payment transaction already used" }];
  const result = await verifyUsdgPayment({
    txHash: h, amount: job.amountBase, merchant: MERCHANT_WALLET, rpcUrl: RPC_URL, notBefore: Date.parse(job.createdAt),
  });
  if (!result.ok) return [402, { error: `payment not verified: ${result.reason}`, jobId: job.id }];
  // Re-check after the await: two concurrent proofs must not both win.
  if (store.findByPayment(h) || store.get(job.id).status !== "pending_payment") return [409, { error: "payment already credited" }];
  store.update(job.id, { status: "paid", paidAt: new Date().toISOString(), paymentTx: h, payer: result.from });
  queue.enqueue(() => runJob(job.id));
  return [202, { jobId: job.id, status: "paid", tx: `${EXPLORER}/tx/${h}` }];
}

// --- agent access -------------------------------------------------------------

function agentAuthorized(req, job) {
  const m = /^Bearer (\S+)$/.exec(req.headers.authorization || "");
  if (!m || !job || !job.accessTokenHash) return false;
  const a = Buffer.from(hashToken(m[1]), "hex");
  const b = Buffer.from(job.accessTokenHash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

function paymentRequired(job, accessToken) {
  const t = paymentTerms(job);
  return {
    error: "payment_required",
    x402Version: 1,
    accepts: [{
      scheme: "exact",
      network: USDG.network,
      asset: USDG.address,
      maxAmountRequired: job.amountBase,
      payTo: MERCHANT_WALLET,
      resource: `${PUBLIC_BASE}/agent/scan`,
      description: `EVM Watchdog dependency + known-class scan of ${job.repo}`,
      mimeType: "application/json",
      maxTimeoutSeconds: Math.round(QUOTE_TTL_MS / 1000),
      extra: { chainId: USDG.chainId, decimals: USDG.decimals, symbol: USDG.symbol, exactAmount: true },
    }],
    jobId: job.id,
    accessToken,
    payment: t,
    x402: facilitator
      ? `Standard x402 v2 clients: pay ${AGENT_SCAN_PRICE_USD} USDC on Base instead, requirements in the PAYMENT-REQUIRED header. Resend this same request with a PAYMENT-SIGNATURE header; the facilitator pays the gas. A new job and its access token come back in the paid response.`
      : undefined,
    howToPay: `${t.note} Then POST ${PUBLIC_BASE}/agent/scan with {"jobId":"${job.id}","txHash":"0x…"}. Keep accessToken: it is shown once and is the only way to read the report.`,
    manual: `${PUBLIC_BASE}/skill.md`,
  };
}

// --- x402 v2 on Base ------------------------------------------------------------

// Our terms, rebuilt on every call: the copy a client echoes back in `accepted`
// is never what we settle against, so it cannot lower the amount or redirect it.
function baseRequirements() {
  return {
    scheme: "exact",
    network: BASE_MAINNET,
    amount: toBase(AGENT_SCAN_PRICE_USD).toString(),
    asset: BASE_USDC.address,
    payTo: MERCHANT_WALLET,
    maxTimeoutSeconds: 300,
    extra: { name: BASE_USDC.name, version: BASE_USDC.version },
  };
}

const SCAN_BAZAAR = bazaarExtension({
  exampleBody: { repo: "https://github.com/morpho-org/morpho-blue" },
  properties: {
    repo: { type: "string", description: "Public GitHub repository URL, https://github.com/<owner>/<repo>" },
    email: { type: "string", description: "Optional. Also email the report here." },
  },
  required: ["repo"],
  outputExample: {
    jobId: "8f0c6a2e-1b7d-4c1e-9d3a-2f5e6b7c8d9e",
    status: "paid",
    accessToken: "<shown once, send as Authorization: Bearer>",
    statusUrl: `${PUBLIC_BASE}/agent/jobs/8f0c6a2e-1b7d-4c1e-9d3a-2f5e6b7c8d9e`,
  },
});

function x402Required(error = "PAYMENT-SIGNATURE header is required") {
  return {
    x402Version: 2,
    error,
    resource: {
      url: `${PUBLIC_BASE}/agent/scan`,
      description: "EVM Watchdog: npm/Foundry dependency advisories split by on-chain vs toolchain surface, plus known Solidity bug-class leads, for a public GitHub repo. A scan, not an audit.",
      mimeType: "application/json",
      serviceName: "EVM Watchdog",
      tags: ["security", "solidity", "evm", "dependencies", "code-scan"],
    },
    accepts: [baseRequirements()],
    extensions: { bazaar: SCAN_BAZAAR },
  };
}
const quoteHeaders = (error) => (facilitator ? { "payment-required": encodeHeader(x402Required(error)) } : {});

// An EIP-3009 authorization can be settled once on-chain, but two copies racing
// through /verify could both look valid: the first one in holds the signature.
const settling = new Set();

async function settleX402(res, payload, body) {
  const acc = payload.accepted || {};
  if (acc.network !== BASE_MAINNET || acc.scheme !== "exact")
    return send(res, 402, { error: `this endpoint settles x402 "exact" on ${BASE_MAINNET} only` }, quoteHeaders());
  let repoInfo;
  try { repoInfo = parseGithubUrl(body.repo || ""); } catch (e) { return send(res, 400, { error: e.message }); }
  if (body.email && !validEmail(body.email)) return send(res, 400, { error: "email is optional, but this one is not valid" });
  const sig = String((payload.payload && payload.payload.signature) || "").toLowerCase();
  if (!sig) return send(res, 400, { error: "PAYMENT-SIGNATURE carries no signature" });
  if (settling.has(sig) || store.list((j) => j.authSig === sig).length) return send(res, 409, { error: "payment already used" });
  settling.add(sig);
  try {
    const reqs = baseRequirements();
    let v;
    try { v = await facilitator.verify(payload, reqs); }
    catch (e) { return send(res, 502, { error: `facilitator unreachable: ${e.message}` }); }
    if (!v.isValid) {
      const error = `payment not valid: ${v.invalidReason || "rejected by facilitator"}`;
      return send(res, 402, { error }, quoteHeaders(error));
    }
    let s;
    try { s = await facilitator.settle(payload, reqs); }
    catch (e) {
      // Unknown outcome: the transfer may have landed. Keep the signature so a
      // retry cannot pay twice; support can match it from the admin list.
      store.create({ repo: repoInfo.url, email: body.email || null, agent: true, status: "settle_unknown", authSig: sig, via: "x402", network: "base", error: String(e.message).slice(0, 300) });
      return send(res, 502, { error: "settlement outcome unknown, do not pay again", contact: CONTACT });
    }
    if (!s.success || !s.transaction) {
      const error = `settlement failed: ${s.errorReason || "unknown"}`;
      return send(res, 402, { error }, { ...quoteHeaders(error), "payment-response": encodeHeader(s) });
    }
    const h = String(s.transaction).toLowerCase();
    // Trust the chain, not the facilitator's word: the same receipt check as USDG.
    const chain = await verifyUsdgPayment({
      txHash: h, amount: reqs.amount, merchant: MERCHANT_WALLET, rpcUrl: BASE_RPC_URL,
      token: BASE_USDC.address, symbol: BASE_USDC.symbol, chainId: BASE_USDC.chainId,
    });
    if (!chain.ok || store.findByPayment(h)) {
      store.create({ repo: repoInfo.url, email: body.email || null, agent: true, status: "settle_unknown", authSig: sig, paymentTx: h, via: "x402", network: "base", error: `facilitator settled but chain check failed: ${chain.reason || "tx reused"}` });
      return send(res, 502, { error: "payment reported settled but not confirmed on-chain yet, do not pay again", transaction: h, contact: CONTACT });
    }
    const accessToken = randomBytes(24).toString("base64url");
    const job = store.create({
      repo: repoInfo.url, email: body.email || null, agent: true, accessTokenHash: hashToken(accessToken),
      priceUsd: AGENT_SCAN_PRICE_USD, amountBase: reqs.amount, status: "paid", paidAt: new Date().toISOString(),
      paymentTx: h, payer: chain.from, authSig: sig, via: "x402", network: "base",
    });
    queue.enqueue(() => runJob(job.id));
    return send(res, 200, {
      jobId: job.id, status: "paid", repo: job.repo, accessToken,
      statusUrl: `${PUBLIC_BASE}/agent/jobs/${job.id}`,
      poll: "GET statusUrl with Authorization: Bearer <accessToken> every 15s; a scan takes about a minute. accessToken is shown once.",
      tx: `https://basescan.org/tx/${h}`,
    }, { "payment-response": encodeHeader(s) });
  } finally {
    settling.delete(sig);
  }
}

// --- per-request advisory check (x402, USDC on Base) ------------------------------
// No repo, no job: the pinned npm packages in the body, their advisories in the
// answer. The payment is verified first and settled only once the answer exists,
// so a lookup that fails costs the agent nothing.

const CHECK_BAZAAR = bazaarExtension({
  exampleBody: { packages: [{ name: "@openzeppelin/contracts", version: "4.8.0" }] },
  properties: {
    packages: {
      type: "array", minItems: 1, maxItems: CHECK_MAX_PACKAGES,
      description: "npm packages at the exact versions pinned in the lockfile (OpenZeppelin, solmate, Uniswap, Chainlink, hardhat…). Send this OR lockfile.",
      items: { type: "object", properties: { name: { type: "string" }, version: { type: "string" } }, required: ["name", "version"] },
    },
    lockfile: {
      type: "string", maxLength: LOCKFILE_MAX_BYTES,
      description: `The raw text of a package-lock.json or yarn.lock (up to ${LOCKFILE_MAX_PACKAGES} registry packages; workspace, file and git deps are skipped). Send this OR packages.`,
    },
  },
  outputExample: {
    checked: 1,
    advisories: [{ id: "GHSA-93hq-5wgc-jc82", packages: ["@openzeppelin/contracts 4.8.0"], severity: "HIGH", summary: "GovernorCompatibilityBravo may trim proposal calldata", url: "https://github.com/advisories/GHSA-93hq-5wgc-jc82" }],
    notCheckedCount: 0,
  },
});

// Either {packages} or {lockfile}. Returns the packages and, for a lockfile, what was read.
function parseCheckInput(body) {
  if (body && body.lockfile !== undefined) {
    if (body.packages !== undefined) throw new Error("send packages OR lockfile, not both");
    if (typeof body.lockfile !== "string") throw new Error("lockfile must be the text of a package-lock.json or yarn.lock");
    if (body.lockfile.length > LOCKFILE_MAX_BYTES) throw new Error(`lockfile is over ${LOCKFILE_MAX_BYTES} bytes`);
    const lf = parseLockfileText(body.lockfile);
    if (!lf) throw new Error("lockfile must be the text of a package-lock.json or yarn.lock");
    if (!lf.packages.length) throw new Error("no registry package in this lockfile");
    if (lf.packages.length > LOCKFILE_MAX_PACKAGES) throw new Error(`lockfile has over ${LOCKFILE_MAX_PACKAGES} registry packages`);
    return { packages: lf.packages, lockfile: { type: lf.type, packages: lf.packages.length, skipped: lf.skipped } };
  }
  return { packages: parsePackages(body) };
}

function parsePackages(body) {
  const pk = body && body.packages;
  if (!Array.isArray(pk) || pk.length === 0 || pk.length > CHECK_MAX_PACKAGES)
    throw new Error(`packages must be a list of 1 to ${CHECK_MAX_PACKAGES} {name, version}`);
  return pk.map((p, i) => {
    const name = p && String(p.name || ""), version = p && String(p.version || "");
    if (!/^(@[a-z0-9._~-]{1,100}\/)?[a-z0-9._~-]{1,214}$/i.test(name) || !/^[0-9A-Za-z.+-]{1,64}$/.test(version))
      throw new Error(`packages[${i}] is not an npm {name, version}`);
    return { name, version };
  });
}

const checkRequirements = () => ({ ...baseRequirements(), amount: toBase(CHECK_PRICE_USD).toString(), maxTimeoutSeconds: 120 });

function checkRequired(error = "PAYMENT-SIGNATURE header is required") {
  return {
    x402Version: 2,
    error,
    resource: {
      url: `${PUBLIC_BASE}/agent/check`,
      description: `EVM Watchdog advisory check: GitHub/OSV advisories affecting the packages of a whole package-lock.json or yarn.lock (or up to ${CHECK_MAX_PACKAGES} listed npm packages) at their exact pinned versions. Instant, per request.`,
      mimeType: "application/json",
      serviceName: "EVM Watchdog check",
      tags: ["security", "solidity", "npm", "advisories", "dependencies"],
    },
    accepts: [checkRequirements()],
    extensions: { bazaar: CHECK_BAZAAR },
  };
}

// One paid answer per request: verify the payment, compute, settle only once the
// answer exists. compute() returns { body, record } or { status, error } (nothing charged).
async function paidRequest(req, res, { requirements, required, priceUsd, kind, compute }) {
  const quote = (error) => ({ "payment-required": encodeHeader(required(error)) });
  const header = req.headers["payment-signature"];
  if (!header) return send(res, 402, { error: "payment_required", priceUsdc: priceUsd, x402: "USDC on Base. Requirements are in the PAYMENT-REQUIRED header; resend with PAYMENT-SIGNATURE.", manual: `${PUBLIC_BASE}/skill.md` }, quote());
  const payload = decodeHeader(header);
  if (!payload || payload.x402Version !== 2 || !payload.payload || !payload.accepted)
    return send(res, 400, { error: "PAYMENT-SIGNATURE is not a base64 x402 v2 PaymentPayload" });
  if (payload.accepted.network !== BASE_MAINNET || payload.accepted.scheme !== "exact")
    return send(res, 402, { error: `this endpoint settles x402 "exact" on ${BASE_MAINNET} only` }, quote("wrong network"));
  const sig = String(payload.payload.signature || "").toLowerCase();
  if (!sig) return send(res, 400, { error: "PAYMENT-SIGNATURE carries no signature" });
  if (settling.has(sig) || store.list((j) => j.authSig === sig).length) return send(res, 409, { error: "payment already used" });
  settling.add(sig);
  try {
    const reqs = requirements();
    let v;
    try { v = await facilitator.verify(payload, reqs); }
    catch (e) { return send(res, 502, { error: `facilitator unreachable, nothing charged: ${e.message}` }); }
    if (!v.isValid) {
      const error = `payment not valid: ${v.invalidReason || "rejected by facilitator"}`;
      return send(res, 402, { error }, quote(error));
    }
    const answer = await compute();
    if (answer.error) return send(res, answer.status || 502, { error: answer.error });
    let s;
    try { s = await facilitator.settle(payload, reqs); }
    catch (e) {
      store.create({ kind, agent: true, status: "settle_unknown", authSig: sig, priceUsd, via: "x402", network: "base", error: String(e.message).slice(0, 300) });
      return send(res, 502, { error: "settlement outcome unknown, do not pay again", contact: CONTACT });
    }
    if (!s.success || !s.transaction) {
      const error = `settlement failed, nothing charged: ${s.errorReason || "unknown"}`;
      return send(res, 402, { error }, { ...quote(error), "payment-response": encodeHeader(s) });
    }
    const h = String(s.transaction).toLowerCase();
    if (store.findByPayment(h)) return send(res, 409, { error: "payment already used" });
    store.create({
      kind, agent: true, status: "done", authSig: sig, paymentTx: h, payer: s.payer || null,
      priceUsd, via: "x402", network: "base", ...answer.record, paidAt: new Date().toISOString(),
    });
    // Anything that must exist only once paid (a watch) is created here, after settlement.
    const extra = answer.commit ? answer.commit(s) : {};
    return send(res, 200, { ...answer.body, ...extra, tx: `https://basescan.org/tx/${h}` }, { "payment-response": encodeHeader(s) });
  } finally {
    settling.delete(sig);
  }
}

async function handleCheck(req, res, body) {
  let packages, lockfile;
  try { ({ packages, lockfile } = parseCheckInput(body)); } catch (e) { return send(res, 400, { error: e.message }); }
  return paidRequest(req, res, {
    requirements: checkRequirements, required: checkRequired, priceUsd: CHECK_PRICE_USD, kind: "check",
    compute: async () => {
      const uniq = [...new Map(packages.map((p) => [`${p.name}@${p.version}`, p])).values()];
      const deps = lockfile ? await scanDependenciesBatch(uniq, globalThis.fetch) : await scanDependencies(uniq, globalThis.fetch);
      if (deps.failures === uniq.length) return { status: 502, error: "advisory database unreachable, nothing charged; try again" };
      return {
        record: { packages: uniq.length, advisoriesFound: deps.advisories.length },
        body: {
          checked: uniq.length - deps.failures,
          advisories: deps.advisories,
          notCheckedCount: deps.failures, // packages the advisory database did not answer for: check them again
          ...(lockfile ? { lockfile } : {}),
          disclaimer: "Known advisories for these exact versions. Not an audit of the code that uses them.",
        },
      };
    },
  });
}

// --- per-request contract check -----------------------------------------------------
// Who can change a deployed contract, and whether its code is public. See contract.mjs.

const CONTRACT_BAZAAR = bazaarExtension({
  exampleBody: { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", chain: "base" },
  properties: {
    address: { type: "string", description: "Address of a deployed contract (0x…)." },
    chain: { type: "string", enum: Object.keys(CONTRACT_CHAINS), description: "base (default) or robinhood (Robinhood Chain)." },
  },
  required: ["address"],
  outputExample: {
    address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", chain: "base",
    proxy: { kind: "transparent-legacy" }, implementation: "0x2ce6311ddae708829bc0784c967b7d77d19fd779",
    upgradeController: { address: "0x…", kind: "single-key", text: "An address with no code: one private key." },
    verified: { contract: "exact_match", implementation: "exact_match" },
    flags: [{ severity: "high", id: "single-key-upgrade", text: "One private key (0x…) can replace this contract's code at any time." }],
  },
});

const contractRequirements = () => ({ ...checkRequirements(), amount: toBase(CONTRACT_PRICE_USD).toString() });

function contractRequired(error = "PAYMENT-SIGNATURE header is required") {
  return {
    x402Version: 2,
    error,
    resource: {
      url: `${PUBLIC_BASE}/agent/contract`,
      description: "Use this before approving or depositing into a contract on Base or Robinhood Chain: is it a proxy, who can change its code (single key, Safe with threshold, timelock with delay), who owns it, is the live code verified on Sourcify. Instant, per request.",
      mimeType: "application/json",
      serviceName: "EVM Watchdog contract",
      tags: ["security", "evm", "base", "proxy", "upgrade", "due-diligence"],
    },
    accepts: [contractRequirements()],
    extensions: { bazaar: CONTRACT_BAZAAR },
  };
}

const chainRpc = (url) => async (method, params) => {
  for (let i = 0; ; i++) {
    const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    if (r.status === 429 && i < 3) { await new Promise((s) => setTimeout(s, 700 * (i + 1))); continue; }
    if (!r.ok) throw new Error(`${method}: HTTP ${r.status}`);
    const j = await r.json();
    if (j.error) throw new Error(`${method}: ${j.error.message || JSON.stringify(j.error)}`);
    return j.result;
  }
};

async function handleContract(req, res, body) {
  const address = body && body.address;
  const chain = (body && body.chain) || "base";
  if (!isAddress(address)) return send(res, 400, { error: "address must be a 0x contract address" });
  if (!CONTRACT_CHAINS[chain]) return send(res, 400, { error: `chain must be one of ${Object.keys(CONTRACT_CHAINS).join(", ")}` });
  return paidRequest(req, res, {
    requirements: contractRequirements, required: contractRequired, priceUsd: CONTRACT_PRICE_USD, kind: "contract",
    compute: async () => {
      let r;
      try { r = await inspectContract(address, { chain, rpc: chainRpc(CONTRACT_CHAINS[chain]) }); }
      catch (e) { return { status: 502, error: `chain lookup failed, nothing charged: ${String(e.message).slice(0, 200)}` }; }
      // Nothing to inspect is not worth a charge: most likely a wrong address or chain.
      if (!r.isContract) return { status: 404, error: `${r.flags[0].text} Nothing charged.` };
      return {
        record: { address: r.address, chain, flags: r.flags.map((f) => f.id) },
        body: { ...r, disclaimer: "Who controls this contract and whether its code is public. Not an audit of its code." },
      };
    },
  });
}

// --- paid watches ------------------------------------------------------------------------
// One payment buys WATCH_DAYS of hourly re-checks of a contract or a lockfile; a change that
// matters is POSTed to the agent's webhook, signed with a secret shown once.

const WATCH_BAZAAR = bazaarExtension({
  exampleBody: { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", chain: "base", webhook: "https://agent.example/hooks/watchdog" },
  properties: {
    address: { type: "string", description: "Watch a deployed contract: implementation swaps, upgrade controller, owner, Safe threshold, timelock delay, verification. Send this OR lockfile." },
    chain: { type: "string", enum: Object.keys(CONTRACT_CHAINS), description: "base (default) or robinhood, with address." },
    lockfile: { type: "string", description: "Watch a package-lock.json or yarn.lock: any new advisory affecting its pinned packages. Send this OR address." },
    webhook: { type: "string", description: "https URL that receives a signed POST on every change (header x-watchdog-signature: sha256=HMAC(secret, body))." },
  },
  required: ["webhook"],
  outputExample: { watchId: "…", secret: "shown once", accessToken: "shown once", expiresAt: "…", baseline: { proxy: { kind: "uups" }, upgradeController: { kind: "timelock", minDelaySeconds: 86400 } } },
});

const watchRequirements = () => ({ ...checkRequirements(), amount: toBase(WATCH_PRICE_USD).toString() });

function watchRequired(error = "PAYMENT-SIGNATURE header is required") {
  return {
    x402Version: 2,
    error,
    resource: {
      url: `${PUBLIC_BASE}/agent/watch`,
      description: `Use this to be told when a contract you rely on (Base, Robinhood Chain) gets new code, a new owner or weaker upgrade rules, or when a new advisory hits your npm lockfile: ${WATCH_DAYS} days of hourly checks, signed webhook on each change. One payment.`,
      mimeType: "application/json",
      serviceName: "EVM Watchdog watch",
      tags: ["security", "evm", "base", "monitoring", "webhook", "proxy", "advisories"],
    },
    accepts: [watchRequirements()],
    extensions: { bazaar: WATCH_BAZAAR },
  };
}

// Re-read a watch's target: { snapshot, events }. Throws when the answer is not
// trustworthy (RPC down, advisory database down), which is never read as "no change".
async function checkWatch(w) {
  if (w.target === "contract") {
    const r = await inspectContract(w.address, { chain: w.chain, rpc: chainRpc(CONTRACT_CHAINS[w.chain]) });
    const snapshot = contractSnapshot(r);
    return { snapshot, events: diffContract(w.snapshot, snapshot) };
  }
  const deps = await scanDependenciesBatch(w.packages, globalThis.fetch);
  if (deps.failures) throw new Error(`advisory database did not answer for ${deps.failures} packages`);
  return { snapshot: lockfileSnapshot(deps.advisories), events: diffLockfile(w.snapshot, lockfileSnapshot(deps.advisories), deps.advisories) };
}

async function handleWatch(req, res, body) {
  if (!body || typeof body.webhook !== "string") return send(res, 400, { error: "webhook (an https URL) is required" });
  let target;
  if (body.address !== undefined) {
    if (body.lockfile !== undefined) return send(res, 400, { error: "send address OR lockfile, not both" });
    const chain = body.chain || "base";
    if (!isAddress(body.address)) return send(res, 400, { error: "address must be a 0x contract address" });
    if (!CONTRACT_CHAINS[chain]) return send(res, 400, { error: `chain must be one of ${Object.keys(CONTRACT_CHAINS).join(", ")}` });
    target = { target: "contract", address: body.address.toLowerCase(), chain, targetSummary: { type: "contract", address: body.address.toLowerCase(), chain } };
  } else {
    let parsed;
    try { parsed = parseCheckInput({ lockfile: body.lockfile }); } catch (e) { return send(res, 400, { error: e.message }); }
    target = { target: "lockfile", packages: parsed.packages, targetSummary: { type: parsed.lockfile.type, packages: parsed.packages.length } };
  }
  try { await checkWebhookUrl(body.webhook, { allowPrivate: WATCH_ALLOW_PRIVATE }); }
  catch (e) { return send(res, 400, { error: e.message }); }
  return paidRequest(req, res, {
    requirements: watchRequirements, required: watchRequired, priceUsd: WATCH_PRICE_USD, kind: "watch",
    compute: async () => {
      // The baseline is taken now, so the first webhook means "changed since you subscribed".
      let baseline, detail;
      try {
        if (target.target === "contract") {
          const r = await inspectContract(target.address, { chain: target.chain, rpc: chainRpc(CONTRACT_CHAINS[target.chain]) });
          if (!r.isContract) return { status: 404, error: `${r.flags[0].text} Nothing charged.` };
          baseline = contractSnapshot(r); detail = { proxy: r.proxy, implementation: r.implementation, upgradeController: r.upgradeController, owner: r.owner, verified: r.verified, flags: r.flags };
        } else {
          const deps = await scanDependenciesBatch(target.packages, globalThis.fetch);
          if (deps.failures === target.packages.length) return { status: 502, error: "advisory database unreachable, nothing charged; try again" };
          baseline = lockfileSnapshot(deps.advisories); detail = { advisories: deps.advisories, notCheckedCount: deps.failures };
        }
      } catch (e) { return { status: 502, error: `lookup failed, nothing charged: ${String(e.message).slice(0, 200)}` }; }
      return {
        record: { watchTarget: target.targetSummary },
        body: { baseline: detail, checksEveryMinutes: Math.round(WATCH_INTERVAL_MS / 60000) },
        commit: () => {
          const secret = newSecret(), accessToken = randomBytes(24).toString("base64url");
          const now = new Date();
          const w = watches.create({
            ...target, status: "active", webhook: body.webhook, secret, accessTokenHash: hashToken(accessToken),
            snapshot: baseline, events: [], lastCheckedAt: now.toISOString(),
            expiresAt: new Date(now.getTime() + WATCH_DAYS * 864e5).toISOString(),
          });
          return {
            watchId: w.id, expiresAt: w.expiresAt,
            secret, // HMAC key for x-watchdog-signature: shown once
            accessToken, // for GET / DELETE on statusUrl: shown once
            statusUrl: `${PUBLIC_BASE}/agent/watch/${w.id}`,
            signature: "x-watchdog-signature: sha256=hex(HMAC-SHA256(secret, raw request body))",
          };
        },
      };
    },
  });
}

function watchView(w) {
  return {
    watchId: w.id, status: w.status, target: w.targetSummary, webhook: w.webhook,
    createdAt: w.createdAt, expiresAt: w.expiresAt, lastCheckedAt: w.lastCheckedAt || null,
    lastError: w.lastError || null, events: w.events || [],
  };
}

const watcher = new Watcher({
  store: watches, check: checkWatch, allowPrivate: WATCH_ALLOW_PRIVATE,
  intervalMs: WATCH_INTERVAL_MS, tickMs: WATCH_TICK_MS, log: (m) => console.log(m),
});

function agentJobView(job) {
  const view = {
    jobId: job.id, status: job.status, repo: job.repo, amount: formatUnits(job.amountBase),
    createdAt: job.createdAt, expiresAt: job.expiresAt, paidAt: job.paidAt || null, deliveredAt: job.deliveredAt || null,
  };
  if (job.status === "error") view.error = job.error;
  if (job.status === "done") {
    const base = `${PUBLIC_BASE}/agent/jobs/${job.id}/report`;
    view.summary = { onchainAdvisories: job.onchainAdvisories, versionsChecked: job.versionsChecked, notChecked: job.notChecked, codeLeads: job.codeLeads };
    view.report = { json: `${base}.json`, markdown: `${base}.md`, html: `${base}.html` };
  }
  return view;
}

// The landing is served from here: same origin as the API, so no CORS and one deploy.
const LANDING_FILE = join(__dirname, "..", "site", "index.html");
const LANDING = existsSync(LANDING_FILE)
  ? readFileSync(LANDING_FILE, "utf8")
    .replaceAll("{{LOGO}}", WATCHDOG_LOGO.replace('width="46" height="46"', 'width="34" height="34"'))
    .replaceAll("{{CONTACT}}", CONTACT)
  : null;
const FAVICON = WATCHDOG_LOGO.replace('width="46" height="46" ', "");

// The ERC-8004 registration file: the agentURI the on-chain identity points to.
// Served from the API's own domain, it also proves control of that endpoint.
function agentRegistration() {
  return {
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name: "EVM Watchdog",
    description: "Security checks for Solidity code and deployed contracts. Who can change a contract on Base or Robinhood Chain (proxy kind, single key, Safe threshold, timelock delay) and whether its live code is verified, before you approve or deposit; npm advisories for a lockfile; and a full scan of a public Solidity GitHub repo (Foundry or Hardhat): advisories on the exact pinned versions of npm, soldeer and git-submodule dependencies, split into the on-chain surface and the toolchain, unresolved dependencies listed as not checked, and leads for 14 known Solidity bug classes with file:line. JSON + Markdown + HTML report. Agents pay per call over x402 (USDC on Base). A scan, not an audit.",
    image: `${PUBLIC_BASE}/favicon.svg`,
    services: [
      { name: "web", endpoint: `${PUBLIC_BASE}/` },
      { name: "x402", endpoint: `${PUBLIC_BASE}/agent/scan` },
      { name: "x402", endpoint: `${PUBLIC_BASE}/agent/contract` },
      { name: "x402", endpoint: `${PUBLIC_BASE}/agent/check` },
      { name: "x402", endpoint: `${PUBLIC_BASE}/agent/watch` },
      { name: "agent-manual", endpoint: `${PUBLIC_BASE}/skill.md` },
    ],
    x402Support: Boolean(facilitator),
    active: true,
    registrations: ERC8004_AGENT_ID === null ? [] : [{ agentId: ERC8004_AGENT_ID, agentRegistry: ERC8004_REGISTRY }],
    supportedTrust: ["reputation"],
  };
}

const SKILL_MD = existsSync(join(__dirname, "skill.md")) ? readFileSync(join(__dirname, "skill.md"), "utf8") : "";

// Provider RPC URLs carry their API key in the path: log the host only.
function rpcHost(u) { try { return new URL(u).host; } catch { return "(unparseable RPC URL)"; } }

const server = createServer(async (req, res) => {
  const ip = req.headers["fly-client-ip"] || req.socket.remoteAddress || "?";
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === "OPTIONS") return send(res, 204, "");

  try {
    if (req.method === "GET" && url.pathname === "/health") return send(res, 200, { ok: true, facilitatorLane: payaiAuth ? "payai" : payaiAuthError ? "public-key-ignored" : "public" });

    if (req.method === "GET" && url.pathname === "/" && LANDING) {
      return send(res, 200, LANDING, { "content-type": "text/html; charset=utf-8", "cache-control": "no-cache", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" });
    }
    // The private report link from the email: /r/<jobId>/<token>
    if (req.method === "GET" && url.pathname.startsWith("/r/")) {
      const m = /^\/r\/([0-9a-f-]{36})\/([A-Za-z0-9_-]{20,64})$/.exec(url.pathname);
      const job = m && store.get(m[1]);
      const ok = job && job.viewTokenHash && (() => {
        const a = Buffer.from(hashToken(m[2]), "hex"), b = Buffer.from(job.viewTokenHash, "hex");
        return a.length === b.length && timingSafeEqual(a, b);
      })();
      const f = ok && join(REPORTS_DIR, `${job.id}.html`);
      if (!ok || !existsSync(f)) return send(res, 404, "Report not found. Check the link in your email.");
      return send(res, 200, readFileSync(f, "utf8"), { "content-type": "text/html; charset=utf-8", "x-robots-tag": "noindex, nofollow", "referrer-policy": "no-referrer", "cache-control": "private, no-store" });
    }
    if (req.method === "GET" && url.pathname === "/favicon.svg") {
      return send(res, 200, FAVICON, { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" });
    }

    if (req.method === "GET" && url.pathname === "/.well-known/agent-registration.json") {
      return send(res, 200, agentRegistration(), { "cache-control": "public, max-age=300" });
    }

    if (req.method === "GET" && (url.pathname === "/skill.md" || url.pathname === "/agent")) {
      return send(res, 200, SKILL_MD
        .replaceAll("{{BASE}}", PUBLIC_BASE)
        .replaceAll("{{PRICE}}", String(AGENT_SCAN_PRICE_USD))
        .replaceAll("{{CHECK_PRICE}}", String(CHECK_PRICE_USD))
        .replaceAll("{{CONTRACT_PRICE}}", String(CONTRACT_PRICE_USD))
        .replaceAll("{{WATCH_PRICE}}", String(WATCH_PRICE_USD))
        .replaceAll("{{WATCH_DAYS}}", String(WATCH_DAYS))
        .replaceAll("{{CHECK_MAX}}", String(CHECK_MAX_PACKAGES))
        .replaceAll("{{TOKEN}}", USDG.address)
        .replaceAll("{{MERCHANT}}", MERCHANT_WALLET || "(not configured)"), { "content-type": "text/markdown; charset=utf-8" });
    }

    // What the landing needs to build the transfer.
    if (req.method === "GET" && url.pathname === "/pay/config") {
      return send(res, 200, { chainId: USDG.chainId, token: USDG.address, symbol: USDG.symbol, decimals: USDG.decimals, payTo: MERCHANT_WALLET, priceUsd: PRICE_USD, explorer: EXPLORER });
    }

    if (req.method === "POST" && url.pathname === "/scan") {
      if (!MERCHANT_WALLET) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip)) return send(res, 429, { error: "rate limited" });
      const body = await readBody(req);
      let repoInfo;
      try { repoInfo = parseGithubUrl(body.repo || ""); } catch (e) { return send(res, 400, { error: e.message }); }
      if (!validEmail(body.email)) return send(res, 400, { error: "valid email required" });
      const job = createQuote({ repo: repoInfo.url, email: body.email });
      return send(res, 201, { jobId: job.id, status: job.status, priceUsd: PRICE_USD, payment: paymentTerms(job) });
    }

    if (req.method === "POST" && url.pathname === "/pay/verify") {
      if (!MERCHANT_WALLET) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip)) return send(res, 429, { error: "rate limited" });
      const body = await readBody(req);
      const job = store.get(body.jobId);
      if (!job || job.agent) return send(res, 404, { error: "unknown jobId" });
      const [code, out] = await claimPayment(job, body.txHash);
      return send(res, code, out);
    }

    if (req.method === "POST" && url.pathname === "/agent/scan") {
      if (!MERCHANT_WALLET) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip)) return send(res, 429, { error: "rate limited" });
      const body = await readBody(req);
      // x402 v2: the same request resent with a signed USDC authorization on Base.
      if (req.headers["payment-signature"]) {
        if (!facilitator) return send(res, 400, { error: "x402 settlement is off here; use the USDG flow in /skill.md" });
        const payload = decodeHeader(req.headers["payment-signature"]);
        if (!payload || payload.x402Version !== 2 || !payload.payload || !payload.accepted)
          return send(res, 400, { error: "PAYMENT-SIGNATURE is not a base64 x402 v2 PaymentPayload" });
        return settleX402(res, payload, body);
      }
      if (req.headers["x-payment"])
        return send(res, 400, { error: "x402 v1 X-PAYMENT is not accepted: use x402 v2 (PAYMENT-SIGNATURE, requirements in the PAYMENT-REQUIRED header) or the USDG flow in /skill.md" });
      if (body.jobId || body.txHash) {
        const job = store.get(body.jobId);
        if (!job || !job.agent) return send(res, 404, { error: "unknown jobId" });
        const [code, out] = await claimPayment(job, body.txHash);
        if (code === 202) Object.assign(out, { statusUrl: `${PUBLIC_BASE}/agent/jobs/${job.id}`, poll: "GET statusUrl with Authorization: Bearer <accessToken> every 15s; a scan takes about a minute." });
        return send(res, code, out);
      }
      let repoInfo;
      try { repoInfo = parseGithubUrl(body.repo || ""); } catch (e) { return send(res, 400, { error: e.message }); }
      if (body.email && !validEmail(body.email)) return send(res, 400, { error: "email is optional, but this one is not valid" });
      const accessToken = randomBytes(24).toString("base64url");
      const job = createQuote({ repo: repoInfo.url, email: body.email || null, agent: true, accessTokenHash: hashToken(accessToken) }, AGENT_SCAN_PRICE_USD, AGENT_AMOUNT_SPREAD);
      return send(res, 402, paymentRequired(job, accessToken), quoteHeaders());
    }

    if (req.method === "POST" && url.pathname === "/agent/contract") {
      if (!MERCHANT_WALLET || !facilitator) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip, 120)) return send(res, 429, { error: "rate limited" });
      let body;
      try { body = await readBody(req); } catch { return send(res, 400, { error: "bad json" }); }
      return handleContract(req, res, body);
    }

    if (req.method === "POST" && url.pathname === "/agent/check") {
      if (!MERCHANT_WALLET || !facilitator) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip, 120)) return send(res, 429, { error: "rate limited" });
      let body;
      try { body = await readBody(req, LOCKFILE_MAX_BYTES + 1e4); } catch { return send(res, 400, { error: "bad json" }); }
      return handleCheck(req, res, body);
    }

    if (req.method === "POST" && url.pathname === "/agent/watch") {
      if (!MERCHANT_WALLET || !facilitator) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip, 60)) return send(res, 429, { error: "rate limited" });
      let body;
      try { body = await readBody(req, LOCKFILE_MAX_BYTES + 1e4); } catch { return send(res, 400, { error: "bad json" }); }
      return handleWatch(req, res, body);
    }

    if ((req.method === "GET" || req.method === "DELETE") && url.pathname.startsWith("/agent/watch/")) {
      const m = /^\/agent\/watch\/([0-9a-f-]{36})$/.exec(url.pathname);
      const w = m && watches.get(m[1]);
      if (!w || !agentAuthorized(req, w)) return send(res, 404, { error: "unknown watchId or wrong access token" });
      if (req.method === "DELETE") return send(res, 200, watchView(watches.update(w.id, { status: "cancelled" })));
      return send(res, 200, watchView(w));
    }

    if (req.method === "GET" && url.pathname.startsWith("/agent/jobs/")) {
      const m = /^\/agent\/jobs\/([0-9a-f-]{36})(?:\/report\.(json|md|html))?$/.exec(url.pathname);
      if (!m) return send(res, 404, { error: "not found" });
      const job = store.get(m[1]);
      if (!job || !job.agent || !agentAuthorized(req, job)) return send(res, 404, { error: "unknown jobId or wrong access token" });
      if (!m[2]) return send(res, 200, agentJobView(job));
      if (job.status !== "done") return send(res, 409, { error: `report not ready, job is ${job.status}` });
      const f = join(REPORTS_DIR, `${job.id}.${m[2]}`);
      if (!existsSync(f)) return send(res, 410, { error: "report no longer stored" });
      const types = { json: "application/json", md: "text/markdown; charset=utf-8", html: "text/html; charset=utf-8" };
      return send(res, 200, readFileSync(f, "utf8"), { "content-type": types[m[2]] });
    }

    // Manual override (a payment made to a wrong amount, support cases).
    if (req.method === "POST" && url.pathname === "/confirm") {
      if (!ADMIN_TOKEN) return send(res, 500, { error: "ADMIN_TOKEN not configured" });
      if ((req.headers.authorization || "") !== `Bearer ${ADMIN_TOKEN}`) return send(res, 401, { error: "unauthorized" });
      const body = await readBody(req);
      const job = store.get(body.jobId);
      if (!job) return send(res, 404, { error: "unknown jobId" });
      if (job.status === "done" || job.status === "running") return send(res, 409, { error: `job already ${job.status}` });
      store.update(job.id, { status: "paid", paidAt: new Date().toISOString(), confirmedBy: "admin" });
      queue.enqueue(() => runJob(job.id));
      return send(res, 202, { jobId: job.id, status: "paid", queued: true });
    }

    if (req.method === "GET" && url.pathname.startsWith("/jobs/")) {
      const job = store.get(url.pathname.split("/")[2]);
      if (!job) return send(res, 404, { error: "unknown jobId" });
      // never leak the email or an agent job's token hash on a public endpoint
      const { email, accessTokenHash, viewTokenHash, ...safe } = job;
      return send(res, 200, safe);
    }

    if (req.method === "GET" && url.pathname === "/admin/jobs") {
      if (!ADMIN_TOKEN || (req.headers.authorization || "") !== `Bearer ${ADMIN_TOKEN}`) return send(res, 401, { error: "unauthorized" });
      return send(res, 200, store.list());
    }

    return send(res, 404, { error: "not found" });
  } catch (e) {
    return send(res, 400, { error: e.message });
  }
});

watcher.start();
server.listen(PORT, () => {
  console.log(`[server] facilitator lane: ${payaiAuth ? `PayAI ${payaiAuth.label()}` : payaiAuthError ? "public, PAYAI KEY IGNORED" : "public (no key)"}`);
  if (payaiAuthError) console.error(`[server] ERROR PayAI key ignored: ${payaiAuthError}`);
  console.log(`[server] EVM Watchdog scan backend on :${PORT}`);
  console.log(`[server] admin ${ADMIN_TOKEN ? "enabled" : "DISABLED (set ADMIN_TOKEN)"} · email ${process.env.RESEND_API_KEY ? "Resend" : "DEV mode (disk)"} · price ${PRICE_USD} USDG web · agents ${AGENT_SCAN_PRICE_USD} scan / ${CHECK_PRICE_USD} check`);
  console.log(`[server] payments ${MERCHANT_WALLET ? "on -> " + MERCHANT_WALLET : "OFF (set MERCHANT_WALLET)"} · chain ${USDG.chainId} · rpc ${rpcHost(RPC_URL)}`);
  console.log(`[server] x402 ${facilitator ? `USDC on Base via ${rpcHost(FACILITATOR_URL)} · base rpc ${rpcHost(BASE_RPC_URL)}` : "OFF"}`);
});

export { server };
