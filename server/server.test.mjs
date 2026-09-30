// node --test server/server.test.mjs — offline: a fake EVM RPC stands in for Robinhood Chain.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyFromReceipt, USDG, TRANSFER_TOPIC, formatUnits, toBase } from "./verify.mjs";
import { Store } from "./store.mjs";
import { encodeHeader, decodeHeader, BASE_MAINNET, BASE_USDC } from "./x402.mjs";

const MERCHANT = "0x0e659996c75dcb352e95e130d79831e3e2fa82a8";
const PAYER = "0x1111111111111111111111111111111111111111";
const FAKE_USDG = "0xa913c4c2f28aa7b0b15a7c6008a6e19ff8bf85c0";
const pad = (a) => "0x" + a.slice(2).padStart(64, "0");
const word = (n) => "0x" + BigInt(n).toString(16).padStart(64, "0");

function receipt({ amount, token = USDG.address, to = MERCHANT, status = "0x1" }) {
  return {
    status, blockNumber: "0x10",
    logs: [{ address: token, topics: [TRANSFER_TOPIC, pad(PAYER), pad(to)], data: word(amount), removed: false }],
  };
}
const block = (ms) => ({ timestamp: "0x" + Math.floor(ms / 1000).toString(16) });

test("only the exact quoted amount of the real USDG to the merchant, after the quote, pays", () => {
  const now = Date.now(), opts = { amount: "69012345", merchant: MERCHANT, notBefore: now - 1000 };
  assert.equal(verifyFromReceipt(receipt({ amount: 69012345 }), block(now), opts).ok, true);
  assert.equal(verifyFromReceipt(receipt({ amount: 69012345 }), block(now), opts).from, PAYER);
  assert.match(verifyFromReceipt(receipt({ amount: 69012346 }), block(now), opts).reason, /does not equal/);
  assert.match(verifyFromReceipt(receipt({ amount: 69012345, token: FAKE_USDG }), block(now), opts).reason, /no USDG transfer/);
  assert.match(verifyFromReceipt(receipt({ amount: 69012345, to: PAYER }), block(now), opts).reason, /no USDG transfer/);
  assert.match(verifyFromReceipt(receipt({ amount: 69012345, status: "0x0" }), block(now), opts).reason, /reverted/);
  assert.match(verifyFromReceipt(receipt({ amount: 69012345 }), block(now - 3600_000), opts).reason, /before this job was quoted/);
  assert.match(verifyFromReceipt(null, null, opts).reason, /not found/);
});

test("amounts: base units without floats, and no two open quotes share one", () => {
  assert.equal(toBase(69).toString(), "69000000");
  assert.equal(formatUnits("69012345"), "69.012345");
  assert.equal(formatUnits("69000001"), "69.000001");
  const s = new Store(join(mkdtempSync(join(tmpdir(), "evmw-store-")), "jobs.json"));
  const seen = new Set();
  for (let i = 0; i < 400; i++) {
    const a = s.uniqueAmount(69_000_000n, 1000, 3600_000);
    assert.ok(!seen.has(a), "duplicate open quote amount");
    assert.ok(BigInt(a) > 69_000_000n && BigInt(a) < 69_001_000n);
    seen.add(a);
    s.create({ amountBase: a });
  }
});

// --- end to end ---------------------------------------------------------------
let rpc, baseRpc, fac, osv, srv, base, osvDown = false;
const osvCalls = [];
const facCalls = [];
const X402_TX = "0x" + "b".repeat(64);
const receipts = new Map();
let chainId = USDG.chainId;
const port = 19000 + Math.floor(Math.random() * 1000);

before(async () => {
  rpc = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const { method, params } = JSON.parse(b);
      const result = method === "eth_chainId" ? "0x" + chainId.toString(16)
        : method === "eth_getTransactionReceipt" ? receipts.get(params[0]) || null
        : method === "eth_getBlockByNumber" ? block(Date.now()) : null;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
    });
  });
  await new Promise((r) => rpc.listen(0, r));
  // Fake Base: the facilitator's settlement tx moves exactly 69 USDC to the merchant.
  baseRpc = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const { method, params } = JSON.parse(b);
      const result = method === "eth_chainId" ? "0x2105"
        : method === "eth_getTransactionReceipt" && params[0] === X402_TX ? receipt({ amount: 500_000, token: BASE_USDC.address })
        : null;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
    });
  });
  await new Promise((r) => baseRpc.listen(0, r));
  // Fake facilitator: signature "0xbad" fails /verify, "0xnosettle" fails /settle.
  fac = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const body = JSON.parse(b);
      facCalls.push({ path: req.url, body });
      const sig = body.paymentPayload.payload.signature;
      res.writeHead(200, { "content-type": "application/json" });
      if (req.url === "/verify") return res.end(JSON.stringify(sig === "0xbad" ? { isValid: false, invalidReason: "invalid_exact_evm_payload_signature" } : { isValid: true, payer: PAYER }));
      const settled = { "0xchk1": "0x" + "c".repeat(64), "0xchk2": "0x" + "d".repeat(64) }[sig] || X402_TX;
      res.end(JSON.stringify(sig === "0xnosettle"
        ? { success: false, errorReason: "insufficient_funds", transaction: "", network: BASE_MAINNET }
        : { success: true, transaction: settled, network: BASE_MAINNET, payer: PAYER }));
    });
  });
  await new Promise((r) => fac.listen(0, r));
  // Fake OSV: @openzeppelin/contracts 4.8.0 carries one advisory, everything else is clean.
  osv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const q = JSON.parse(b);
      osvCalls.push(q);
      if (osvDown) { res.writeHead(500); return res.end(); }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(q.package.name === "@openzeppelin/contracts" ? { vulns: [{ id: "GHSA-93hq-5wgc-jc82", aliases: ["CVE-2023-30542"], summary: "GovernorCompatibilityBravo may trim proposal calldata" }] } : {}));
    });
  });
  await new Promise((r) => osv.listen(0, r));
  base = `http://127.0.0.1:${port}`;
  srv = spawn(process.execPath, [join(dirname(fileURLToPath(import.meta.url)), "index.mjs")], {
    env: {
      ...process.env, PORT: String(port), JOBS_FILE: join(mkdtempSync(join(tmpdir(), "evmw-e2e-")), "jobs.json"),
      MERCHANT_WALLET: MERCHANT, EVM_RPC_URL: `http://127.0.0.1:${rpc.address().port}`, SCAN_PRICE_USD: "69",
      PUBLIC_BASE_URL: base, RESEND_API_KEY: "",
      BASE_RPC_URL: `http://127.0.0.1:${baseRpc.address().port}`, FACILITATOR_URL: `http://127.0.0.1:${fac.address().port}`,
      OSV_QUERY_URL: `http://127.0.0.1:${osv.address().port}`,
    },
    stdio: "ignore",
  });
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(`${base}/health`)).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("server did not start");
});
after(() => { srv?.kill(); rpc?.close(); baseRpc?.close(); fac?.close(); osv?.close(); });

const post = (path, body) => fetch(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
const tx = (n) => "0x" + String(n).repeat(64).slice(0, 64);

test("agent flow: 402 quote, wrong amount refused, exact amount accepted, token-gated, no replay", async () => {
  const skill = await (await fetch(`${base}/skill.md`)).text();
  assert.match(skill, new RegExp(USDG.address));
  assert.match(skill, new RegExp(MERCHANT));
  assert.doesNotMatch(skill, /\{\{/);

  const q = await post("/agent/scan", { repo: "https://github.com/morpho-org/morpho-blue" });
  assert.equal(q.status, 402);
  const quote = await q.json();
  assert.equal(quote.accepts[0].asset, USDG.address);
  assert.equal(quote.accepts[0].payTo, MERCHANT);
  assert.equal(quote.accepts[0].extra.chainId, 4663);
  assert.equal(quote.payment.amountBase, quote.accepts[0].maxAmountRequired);
  // Agents pay $0.50, a unique amount at most 0.009999 above it; the web keeps $69.
  assert.ok(BigInt(quote.payment.amountBase) > 500_000n && BigInt(quote.payment.amountBase) < 510_000n);

  // Someone else's payment of the plain price does not pay this quote.
  receipts.set(tx(1), receipt({ amount: 500_000 }));
  const wrong = await post("/agent/scan", { jobId: quote.jobId, txHash: tx(1) });
  assert.equal(wrong.status, 402);
  assert.match((await wrong.json()).error, /does not equal/);

  receipts.set(tx(2), receipt({ amount: quote.payment.amountBase }));
  const ok = await post("/agent/scan", { jobId: quote.jobId, txHash: tx(2) });
  assert.equal(ok.status, 202);

  assert.equal((await post("/agent/scan", { jobId: quote.jobId, txHash: tx(2) })).status, 409);
  const q2 = await (await post("/agent/scan", { repo: "https://github.com/morpho-org/morpho-blue" })).json();
  assert.notEqual(q2.payment.amountBase, quote.payment.amountBase);
  assert.equal((await post("/agent/scan", { jobId: q2.jobId, txHash: tx(2).toUpperCase().replace("0X", "0x") })).status, 409);

  const status = (id, tok) => fetch(`${base}/agent/jobs/${id}`, { headers: tok ? { authorization: `Bearer ${tok}` } : {} });
  assert.equal((await status(quote.jobId)).status, 404);
  assert.equal((await status(quote.jobId, q2.accessToken)).status, 404);
  assert.equal((await status(quote.jobId, quote.accessToken)).status, 200);
  const pub = await (await fetch(`${base}/jobs/${quote.jobId}`)).json();
  assert.equal(pub.accessTokenHash, undefined);
});

test("web flow and a misconfigured RPC", async () => {
  const cfg = await (await fetch(`${base}/pay/config`)).json();
  assert.equal(cfg.token, USDG.address);
  assert.equal((await post("/scan", { repo: "https://github.com/a/b" })).status, 400); // email required
  const job = await (await post("/scan", { repo: "https://github.com/morpho-org/morpho-blue", email: "a@b.co" })).json();
  receipts.set(tx(3), receipt({ amount: job.payment.amountBase }));
  chainId = 1;
  const bad = await post("/pay/verify", { jobId: job.jobId, txHash: tx(3) });
  assert.equal(bad.status, 402);
  assert.match((await bad.json()).error, /chain 1/);
  chainId = USDG.chainId;
  assert.equal((await post("/pay/verify", { jobId: job.jobId, txHash: tx(3) })).status, 202);
});

test("the landing is served from the API origin, with the logo and contact filled in", async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /text\/html/);
  const html = await res.text();
  assert.match(html, /EVM <span class="g">Watchdog<\/span>/);
  assert.match(html, /<svg/);
  assert.doesNotMatch(html, /\{\{/);
  // The page must pay through the ERC-20 transfer selector, never a raw ETH value transfer.
  assert.match(html, /0xa9059cbb/);
  const fav = await fetch(`${base}/favicon.svg`);
  assert.equal(fav.status, 200);
  assert.match(fav.headers.get("content-type"), /image\/svg\+xml/);
});

test("private report links: a wrong token or an unknown job is a 404, never a report", async () => {
  const job = await (await post("/scan", { repo: "https://github.com/morpho-org/morpho-blue", email: "a@b.co" })).json();
  assert.equal((await fetch(`${base}/r/${job.jobId}/${"x".repeat(32)}`)).status, 404); // not scanned yet, no token
  assert.equal((await fetch(`${base}/r/00000000-0000-0000-0000-000000000000/${"x".repeat(32)}`)).status, 404);
  assert.equal((await fetch(`${base}/r/not-a-uuid/short`)).status, 404);
  const pub = await (await fetch(`${base}/jobs/${job.jobId}`)).json();
  assert.equal("viewTokenHash" in pub, false);
});

test("x402 v2 on Base: header quote, settled on our terms, checked on-chain, no replay", async () => {
  const repo = "https://github.com/morpho-org/morpho-blue";
  const q = await post("/agent/scan", { repo });
  assert.equal(q.status, 402);
  const required = decodeHeader(q.headers.get("payment-required"));
  assert.equal(required.x402Version, 2);
  const [req] = required.accepts;
  assert.equal(req.network, BASE_MAINNET);
  assert.equal(req.asset, BASE_USDC.address);
  assert.equal(req.amount, "500000");
  assert.equal(req.payTo, MERCHANT);
  assert.deepEqual(req.extra, { name: "USD Coin", version: "2" });
  assert.equal(required.extensions.bazaar.info.input.method, "POST");
  assert.ok(required.resource.serviceName.length <= 32 && required.resource.tags.length <= 5);

  const pay = (signature, accepted = req, body = { repo }) => fetch(`${base}/agent/scan`, {
    method: "POST",
    headers: { "content-type": "application/json", "payment-signature": encodeHeader({ x402Version: 2, resource: required.resource, accepted, payload: { signature, authorization: { from: PAYER, to: MERCHANT, value: accepted.amount } }, extensions: required.extensions }) },
    body: JSON.stringify(body),
  });

  assert.equal((await pay("0xbad")).status, 402);
  const failed = await pay("0xnosettle");
  assert.equal(failed.status, 402);
  assert.equal(decodeHeader(failed.headers.get("payment-response")).success, false);
  // A bad repo is refused before anything is settled.
  facCalls.length = 0;
  assert.equal((await pay("0xgood", req, { repo: "nope" })).status, 400);
  assert.equal(facCalls.length, 0);
  // Another chain is not ours to settle.
  assert.equal((await pay("0xgood", { ...req, network: "eip155:1" })).status, 402);

  // A client that lowers the amount in its echo is settled against OUR terms.
  const ok = await pay("0xgood", { ...req, amount: "1", payTo: PAYER });
  assert.equal(ok.status, 200);
  for (const c of facCalls) {
    assert.equal(c.body.paymentRequirements.amount, "500000");
    assert.equal(c.body.paymentRequirements.payTo, MERCHANT);
    assert.equal(c.body.paymentRequirements.asset, BASE_USDC.address);
  }
  assert.equal(decodeHeader(ok.headers.get("payment-response")).transaction, X402_TX);
  const paid = await ok.json();
  const st = await fetch(`${base}/agent/jobs/${paid.jobId}`, { headers: { authorization: `Bearer ${paid.accessToken}` } });
  assert.equal(st.status, 200);
  assert.equal((await st.json()).amount, "0.500000");

  // The same authorization again, even in different case, pays for nothing.
  assert.equal((await pay("0xGOOD")).status, 409);
  const v1 = await fetch(`${base}/agent/scan`, { method: "POST", headers: { "x-payment": "e30=" }, body: JSON.stringify({ repo }) });
  assert.equal(v1.status, 400);
});

test("ERC-8004 registration file: x402 service, own domain, no registration before one exists", async () => {
  const reg = await (await fetch(`${base}/.well-known/agent-registration.json`)).json();
  assert.equal(reg.type, "https://eips.ethereum.org/EIPS/eip-8004#registration-v1");
  assert.equal(reg.x402Support, true);
  assert.ok(reg.services.some((s) => s.name === "x402" && s.endpoint === `${base}/agent/scan`));
  assert.deepEqual(reg.registrations, []);
  assert.equal((await fetch(reg.image)).status, 200);
});

test("per-request check on Base: instant answer, settled only once the answer exists", async () => {
  const check = (body, header) => fetch(`${base}/agent/check`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(header ? { "payment-signature": header } : {}) },
    body: JSON.stringify(body),
  });
  const packages = [{ name: "@openzeppelin/contracts", version: "4.8.0" }, { name: "solmate", version: "6.2.0" }, { name: "@openzeppelin/contracts", version: "4.8.0" }];

  assert.equal((await check({ packages: [] })).status, 400);
  assert.equal((await check({ packages: [{ name: "a b", version: "1" }] })).status, 400);

  const q = await check({ packages });
  assert.equal(q.status, 402);
  const required = decodeHeader(q.headers.get("payment-required"));
  const [req] = required.accepts;
  assert.equal(req.amount, "10000"); // $0.01
  assert.equal(req.network, BASE_MAINNET);
  assert.equal(req.payTo, MERCHANT);
  assert.equal(required.resource.url, `${base}/agent/check`);
  const pay = (signature, accepted = req) => encodeHeader({ x402Version: 2, resource: required.resource, accepted, payload: { signature, authorization: { from: PAYER, to: MERCHANT, value: accepted.amount } }, extensions: required.extensions });

  osvCalls.length = 0;
  assert.equal((await check({ packages }, pay("0xbad"))).status, 402);
  assert.equal(osvCalls.length, 0);

  osvDown = true; facCalls.length = 0;
  assert.equal((await check({ packages }, pay("0xchk1"))).status, 502);
  assert.deepEqual(facCalls.map((c) => c.path), ["/verify"]);
  osvDown = false;

  facCalls.length = 0; osvCalls.length = 0;
  const ok = await check({ packages }, pay("0xchk1", { ...req, amount: "1", payTo: PAYER }));
  assert.equal(ok.status, 200);
  assert.equal(osvCalls.length, 2);
  assert.deepEqual(facCalls.map((c) => c.path), ["/verify", "/settle"]);
  for (const c of facCalls) { assert.equal(c.body.paymentRequirements.amount, "10000"); assert.equal(c.body.paymentRequirements.payTo, MERCHANT); }
  const out = await ok.json();
  assert.equal(out.checked, 2);
  assert.equal(out.advisories.length, 1);
  assert.equal(out.advisories[0].id, "GHSA-93hq-5wgc-jc82");

  assert.equal((await check({ packages }, pay("0xCHK1"))).status, 409);
  assert.equal((await check({ packages }, pay("0xchk2"))).status, 200);
});
