// node --test server/watch.test.mjs
// What counts as a change for a contract or a lockfile, the webhook guards, the scheduler.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import { Store } from "./store.mjs";
import { Watcher, contractSnapshot, diffContract, diffLockfile, lockfileSnapshot, isPrivateAddress, checkWebhookUrl } from "./watch.mjs";

const IMPL = "0x" + "2".repeat(40), IMPL2 = "0x" + "3".repeat(40), SAFE = "0x" + "4".repeat(40), KEY = "0x" + "5".repeat(40), ADMIN = "0x" + "6".repeat(40);
const safe = (threshold, owners = 5) => ({ address: SAFE, kind: "safe", threshold, owners });
const inspected = (over = {}) => ({ isContract: true, proxy: { kind: "transparent" }, implementation: IMPL, upgradeController: { address: ADMIN, kind: "owned-contract", ownedBy: safe(3) }, owner: null, verified: { contract: "exact_match", implementation: "exact_match" }, ...over });
const ids = (events) => events.map((e) => e.type);

test("contract changes that matter, followed through a ProxyAdmin", () => {
  const base = contractSnapshot(inspected());
  assert.deepEqual(base.upgradeController, { kind: "safe", address: SAFE, threshold: 3, owners: 5, minDelaySeconds: null });
  assert.deepEqual(diffContract(base, contractSnapshot(inspected())), []);
  assert.deepEqual(ids(diffContract(base, contractSnapshot(inspected({ implementation: IMPL2 })))), ["implementation-changed"]);
  const weaker = diffContract(base, contractSnapshot(inspected({ upgradeController: { address: ADMIN, kind: "owned-contract", ownedBy: safe(1) } })));
  assert.deepEqual(ids(weaker), ["upgrade-controller-safe-changed"]);
  assert.equal(weaker[0].severity, "high");
  const toKey = diffContract(base, contractSnapshot(inspected({ upgradeController: { address: ADMIN, kind: "owned-contract", ownedBy: { address: KEY, kind: "single-key" } } })));
  assert.deepEqual(ids(toKey), ["upgrade-controller-changed"]);
  assert.equal(toKey[0].severity, "high");
  const tl = (d) => contractSnapshot(inspected({ upgradeController: { address: SAFE, kind: "timelock", minDelaySeconds: d } }));
  assert.equal(diffContract(tl(86400), tl(0))[0].severity, "high");
  assert.deepEqual(ids(diffContract(base, contractSnapshot(inspected({ owner: { address: KEY, kind: "single-key" } })))), ["owner-changed"]);
  assert.deepEqual(ids(diffContract(base, contractSnapshot(inspected({ verified: { implementation: "none" } })))), ["verification-lost"]);
  assert.deepEqual(ids(diffContract(base, contractSnapshot({ isContract: false }))), ["code-removed"]);
});

test("lockfile: only advisories that were not there", () => {
  const now = [{ id: "GHSA-1", packages: ["a 1"] }, { id: "GHSA-2", packages: ["b 2"], severity: "CRITICAL" }];
  const ev = diffLockfile(lockfileSnapshot([{ id: "GHSA-1" }]), lockfileSnapshot(now), now);
  assert.deepEqual(ev.map((e) => [e.type, e.advisory.id, e.severity]), [["new-advisory", "GHSA-2", "high"]]);
  assert.match(ev[0].text, /b 2/);
});

test("webhook guards", async () => {
  for (const ip of ["10.1.2.3", "127.0.0.1", "169.254.169.254", "::1", "fd12::1", "::ffff:192.168.1.1"]) assert.equal(isPrivateAddress(ip), true, ip);
  const resolve = async (h) => ({ "ok.example": [{ address: "93.184.216.34" }], "mixed.example": [{ address: "93.184.216.34" }, { address: "127.0.0.1" }] })[h] || [];
  await checkWebhookUrl("https://ok.example/h", { resolve });
  await assert.rejects(checkWebhookUrl("https://mixed.example/h", { resolve }), /public/);
  await assert.rejects(checkWebhookUrl("http://ok.example/h", { resolve }), /https/);
});

test("scheduler: signed page once per change; a failed lookup is not a change", async () => {
  const store = new Store(join(mkdtempSync(join(tmpdir(), "evm-watch-")), "watches.json"));
  const posts = [];
  let snap = contractSnapshot(inspected()), fail = false;
  const w = new Watcher({
    store, allowPrivate: true, intervalMs: 1000,
    check: async (x) => { if (fail) throw new Error("eth_call: HTTP 429"); return { snapshot: snap, events: diffContract(x.snapshot, snap) }; },
    post: async (url, headers, body) => { posts.push({ headers, body }); return { status: 200 }; },
  });
  const t0 = Date.parse("2026-10-01T00:00:00Z");
  const watch = store.create({ status: "active", target: "contract", targetSummary: {}, webhook: "https://ok.example/h", secret: "k", snapshot: snap, events: [], lastCheckedAt: new Date(t0).toISOString(), expiresAt: new Date(t0 + 60_000).toISOString() });
  fail = true;
  await w.tick(t0 + 1500);
  assert.equal(posts.length, 0);
  assert.equal(store.get(watch.id).checkFailures, 1);
  fail = false;
  snap = contractSnapshot(inspected({ implementation: IMPL2 }));
  await w.tick(t0 + 3000);
  await w.tick(t0 + 4500);
  assert.equal(posts.length, 1);
  assert.equal(posts[0].headers["x-watchdog-signature"], "sha256=" + createHmac("sha256", "k").update(posts[0].body).digest("hex"));
  assert.equal(store.get(watch.id).snapshot.implementation, IMPL2);
});
