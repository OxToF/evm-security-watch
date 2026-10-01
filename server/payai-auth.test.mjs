// node --test server/payai-auth.test.mjs
// The PayAI key: a JWT PayAI can verify, cached and refreshed, sent on every
// facilitator call, and a misconfiguration refused at boot.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { PayAIAuth } from "./payai-auth.mjs";
import { Facilitator } from "./x402.mjs";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const SECRET = "payai_sk_" + privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
const part = (jwt, i) => JSON.parse(Buffer.from(jwt.split(".")[i], "base64url").toString());

test("the JWT is what PayAI checks: EdDSA, kid/sub = key id, 120 s, signed by the key", () => {
  const auth = new PayAIAuth("key_abc123", SECRET, { now: () => 1_700_000_000_000 });
  const jwt = auth.token();
  assert.deepEqual(part(jwt, 0), { alg: "EdDSA", typ: "JWT", kid: "key_abc123" });
  const p = part(jwt, 1);
  assert.equal(p.sub, "key_abc123");
  assert.equal(p.iss, "payai-merchant");
  assert.equal(p.exp - p.iat, 120);
  assert.match(p.jti, /^[0-9a-f-]{36}$/);
  const [h, b, sig] = jwt.split(".");
  assert.equal(verify(null, Buffer.from(`${h}.${b}`), publicKey, Buffer.from(sig, "base64url")), true);
  assert.equal(auth.headers().authorization, `Bearer ${jwt}`);
  assert.doesNotMatch(auth.label(), new RegExp(SECRET.slice(12, 30)));
});

test("cached for its life, renewed 30 s before expiry", () => {
  let t = 1_700_000_000_000;
  const auth = new PayAIAuth("k", SECRET, { now: () => t });
  const first = auth.token();
  t += 80_000;
  assert.equal(auth.token(), first);
  t += 15_000; // 95 s in: inside the last 30 s
  assert.notEqual(auth.token(), first);
});

test("a misconfiguration fails at boot, never at the first payment", () => {
  assert.equal(PayAIAuth.fromEnv({}), null);
  assert.throws(() => PayAIAuth.fromEnv({ PAYAI_API_KEY_ID: "k" }), /both/);
  assert.throws(() => PayAIAuth.fromEnv({ PAYAI_API_KEY_SECRET: SECRET }), /both/);
  assert.throws(() => PayAIAuth.fromEnv({ PAYAI_API_KEY_ID: "k", PAYAI_API_KEY_SECRET: "payai_sk_bm90IGEga2V5" }), /PKCS#8/);
  const rsa = generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
  assert.throws(() => PayAIAuth.fromEnv({ PAYAI_API_KEY_ID: "k", PAYAI_API_KEY_SECRET: rsa }), /Ed25519/);
  // Without the prefix works too.
  assert.ok(PayAIAuth.fromEnv({ PAYAI_API_KEY_ID: "k", PAYAI_API_KEY_SECRET: SECRET.slice(9) }));

});

// 2026-10-01: a masked secret (payai_sk_•••) took both apps down at boot. A bad key
// must keep the server up, on the public lane, without ever sending the key.
test("a bad key does not take the server down: public lane, error at boot and in /health", async () => {
  const server = join(dirname(fileURLToPath(import.meta.url)), "index.mjs");
  const port = 19500 + Math.floor(Math.random() * 400);
  const dir = mkdtempSync(join(tmpdir(), "payai-boot-"));
  const run = (extra) => spawn(process.execPath, [server], { env: { ...process.env, PORT: String(port), JOBS_FILE: join(dir, "jobs.json"), ...extra }, stdio: ["ignore", "pipe", "pipe"] });
  for (const [extra, lane] of [
    [{ PAYAI_API_KEY_ID: "k", PAYAI_API_KEY_SECRET: "payai_sk_" + "\u2022".repeat(64) }, "public-key-ignored"],
    [{ PAYAI_API_KEY_ID: "k" }, "public-key-ignored"],
    [{ PAYAI_API_KEY_ID: "k", PAYAI_API_KEY_SECRET: SECRET }, "payai"],
    [{}, "public"],
  ]) {
    const p = run(extra);
    let err = "", out = "";
    p.stderr.on("data", (d) => (err += d));
    p.stdout.on("data", (d) => (out += d));
    let health = null;
    for (let i = 0; i < 50 && !health; i++) {
      try { health = await (await fetch(`http://127.0.0.1:${port}/health`)).json(); } catch { await new Promise((r) => setTimeout(r, 100)); }
    }
    p.kill();
    await new Promise((r) => p.on("exit", r));
    assert.equal(health && health.facilitatorLane, lane, JSON.stringify(extra).slice(0, 60));
    if (lane === "public-key-ignored") assert.match(err, /PayAI key ignored/);
    assert.ok(!out.includes(SECRET.slice(9, 40)) && !err.includes(SECRET.slice(9, 40)), "secret must never be logged");
  }
});

test("the facilitator sends the token on every call when keyed, and nothing when not", async () => {
  const seen = [];
  const fetchImpl = async (url, opts = {}) => {
    seen.push({ path: new URL(url).pathname, auth: (opts.headers || {}).authorization || null });
    const body = url.endsWith("/supported") ? { kinds: [{ x402Version: 2, scheme: "exact", network: "n", extra: { feePayer: "F" } }] } : { isValid: true, success: true };
    return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
  };
  const keyed = new Facilitator({ url: "https://f.example", fetchImpl, auth: new PayAIAuth("k", SECRET) });
  if (keyed.feePayer) await keyed.feePayer("n");
  await keyed.verify({}, {});
  await keyed.settle({}, {});
  assert.ok(seen.length >= 2);
  for (const s of seen) assert.match(s.auth, /^Bearer [\w-]+\.[\w-]+\.[\w-]+$/, s.path);
  seen.length = 0;
  const open = new Facilitator({ url: "https://f.example", fetchImpl });
  if (open.feePayer) await open.feePayer("n");
  await open.verify({}, {});
  for (const s of seen) assert.equal(s.auth, null, s.path);
});
