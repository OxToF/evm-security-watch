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
let rpc, srv, base;
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
  base = `http://127.0.0.1:${port}`;
  srv = spawn(process.execPath, [join(dirname(fileURLToPath(import.meta.url)), "index.mjs")], {
    env: {
      ...process.env, PORT: String(port), JOBS_FILE: join(mkdtempSync(join(tmpdir(), "evmw-e2e-")), "jobs.json"),
      MERCHANT_WALLET: MERCHANT, EVM_RPC_URL: `http://127.0.0.1:${rpc.address().port}`, SCAN_PRICE_USD: "69",
      PUBLIC_BASE_URL: base, RESEND_API_KEY: "",
    },
    stdio: "ignore",
  });
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(`${base}/health`)).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("server did not start");
});
after(() => { srv?.kill(); rpc?.close(); });

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
  assert.ok(BigInt(quote.payment.amountBase) > 69_000_000n);

  // Someone else's payment of the plain price does not pay this quote.
  receipts.set(tx(1), receipt({ amount: 69_000_000 }));
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
