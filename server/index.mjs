// EVM Watchdog — scan backend. Paid in USDG on Robinhood Chain.
//
// Web flow:   POST /scan {repo,email}        -> job + a unique USDG amount to pay
//             POST /pay/verify {jobId,txHash} -> checks the transfer on-chain, queues
//             the scan, emails the report.
// Agent flow: POST /agent/scan {repo}        -> HTTP 402 with x402-style requirements
//             POST /agent/scan {jobId,txHash} -> same check, then the agent polls
//             GET /agent/jobs/:id with the bearer token it got at quote time.
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
import { runScan, parseGithubUrl, WATCHDOG_LOGO } from "../bin/scan.mjs";
import { Store } from "./store.mjs";
import { Queue } from "./queue.mjs";
import { sendReport } from "./email.mjs";
import { verifyUsdgPayment, USDG, toBase, formatUnits } from "./verify.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const PRICE_USD = Number(process.env.SCAN_PRICE_USD || 69);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "*";
const MERCHANT_WALLET = process.env.MERCHANT_WALLET ? process.env.MERCHANT_WALLET.toLowerCase() : null;
const RPC_URL = process.env.EVM_RPC_URL || "https://rpc.mainnet.chain.robinhood.com";
const QUOTE_TTL_MS = Number(process.env.QUOTE_TTL_HOURS || 24) * 3600_000;
// Unique part of a quote, in base units: up to 0.099999 USDG on top of the price.
const AMOUNT_SPREAD = 100_000;
const JOBS_FILE = process.env.JOBS_FILE || join(__dirname, "data", "jobs.json");
const REPORTS_DIR = process.env.REPORTS_DIR || join(dirname(JOBS_FILE), "reports");
const PUBLIC_BASE = (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const EXPLORER = "https://robinhoodchain.blockscout.com";
const SUPPORT = process.env.SUPPORT_EMAIL || null;

if (MERCHANT_WALLET && !/^0x[0-9a-f]{40}$/.test(MERCHANT_WALLET)) throw new Error("MERCHANT_WALLET is not an 0x address");

const store = new Store(JOBS_FILE);
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
    "access-control-allow-methods": "POST, GET, OPTIONS",
    "access-control-allow-headers": "content-type, authorization",
    ...extraHeaders,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 1e5) req.destroy(); });
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
    result = await runScan({ repoUrl: job.repo, out, log: () => {} });
    const html = readFileSync(result.htmlPath, "utf8");
    const md = readFileSync(result.mdPath, "utf8");
    const sum = summarize(result);
    if (job.agent) {
      mkdirSync(REPORTS_DIR, { recursive: true });
      writeFileSync(join(REPORTS_DIR, `${jobId}.html`), html);
      writeFileSync(join(REPORTS_DIR, `${jobId}.md`), md);
      writeFileSync(join(REPORTS_DIR, `${jobId}.json`), JSON.stringify(sum, null, 2) + "\n");
    }
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
      text: `Scan complete for ${job.repo}.\n\n${headline}\n${c.toolchainAdvisories} more in toolchain/test packages, ${c.dependenciesNotChecked} dependencies not checked, ${c.codeLeads} code leads.\n\n${top}\n\nFull report attached. A scan, not an audit.`,
      html: `<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:560px;margin:auto;background:#fff;border-radius:14px;overflow:hidden;border:1px solid #eaecf3">
<div style="background:#160b2e;padding:18px 22px;border-bottom:3px solid #14F195">
<span style="color:#fff;font-weight:800;letter-spacing:.5px;font-size:16px">EVM <span style="color:#14F195">WATCHDOG</span></span>
<div style="color:#a9b0cf;font-size:12px;margin-top:3px">Dependency &amp; known-class security scan</div></div>
<div style="padding:22px">
<p style="margin:0 0 12px;font-size:15px;color:#1c2030">Scan complete for <b>${sum.repo}</b>.</p>
<p style="margin:0 0 14px;color:#1c2030">${headline}<br><b>${c.toolchainAdvisories}</b> in toolchain / test packages &middot; <b>${c.dependenciesNotChecked}</b> dependencies not checked &middot; <b>${c.codeLeads}</b> code leads</p>
${top ? `<div style="background:#f7f8fc;border:1px solid #eaecf3;border-radius:10px;padding:12px 14px;font-size:13px;color:#333;white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace">${top.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>` : ""}
<p style="margin:16px 0 0;color:#1c2030">The full report is attached &mdash; open the <b>.html</b> for the branded version.</p>
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

function createQuote(fields) {
  const amountBase = store.uniqueAmount(toBase(PRICE_USD), AMOUNT_SPREAD, QUOTE_TTL_MS);
  return store.create({ ...fields, priceUsd: PRICE_USD, amountBase, expiresAt: new Date(Date.now() + QUOTE_TTL_MS).toISOString() });
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
    howToPay: `${t.note} Then POST ${PUBLIC_BASE}/agent/scan with {"jobId":"${job.id}","txHash":"0x…"}. Keep accessToken: it is shown once and is the only way to read the report.`,
    manual: `${PUBLIC_BASE}/skill.md`,
  };
}

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
    .replaceAll("{{CONTACT}}", SUPPORT || "solanawatchdog@proton.me")
  : null;
const FAVICON = WATCHDOG_LOGO.replace('width="46" height="46" ', "");

const SKILL_MD = existsSync(join(__dirname, "skill.md")) ? readFileSync(join(__dirname, "skill.md"), "utf8") : "";

// Provider RPC URLs carry their API key in the path: log the host only.
function rpcHost(u) { try { return new URL(u).host; } catch { return "(unparseable RPC URL)"; } }

const server = createServer(async (req, res) => {
  const ip = req.headers["fly-client-ip"] || req.socket.remoteAddress || "?";
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === "OPTIONS") return send(res, 204, "");

  try {
    if (req.method === "GET" && url.pathname === "/health") return send(res, 200, { ok: true });

    if (req.method === "GET" && url.pathname === "/" && LANDING) {
      return send(res, 200, LANDING, { "content-type": "text/html; charset=utf-8", "cache-control": "no-cache", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" });
    }
    if (req.method === "GET" && url.pathname === "/favicon.svg") {
      return send(res, 200, FAVICON, { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" });
    }

    if (req.method === "GET" && (url.pathname === "/skill.md" || url.pathname === "/agent")) {
      return send(res, 200, SKILL_MD
        .replaceAll("{{BASE}}", PUBLIC_BASE)
        .replaceAll("{{PRICE}}", String(PRICE_USD))
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
      const job = createQuote({ repo: repoInfo.url, email: body.email || null, agent: true, accessTokenHash: hashToken(accessToken) });
      return send(res, 402, paymentRequired(job, accessToken));
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
      const { email, accessTokenHash, ...safe } = job;
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

server.listen(PORT, () => {
  console.log(`[server] EVM Watchdog scan backend on :${PORT}`);
  console.log(`[server] admin ${ADMIN_TOKEN ? "enabled" : "DISABLED (set ADMIN_TOKEN)"} · email ${process.env.RESEND_API_KEY ? "Resend" : "DEV mode (disk)"} · price ${PRICE_USD} USDG`);
  console.log(`[server] payments ${MERCHANT_WALLET ? "on -> " + MERCHANT_WALLET : "OFF (set MERCHANT_WALLET)"} · chain ${USDG.chainId} · rpc ${rpcHost(RPC_URL)}`);
});

export { server };
