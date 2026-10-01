// node --test server/contract.test.mjs
// Contract inspection against a fake chain: proxy kinds, controllers followed to
// the end, the flags, and transport errors that must not pass for answers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { inspectContract, classify, isAddress } from "./contract.mjs";

const A = (n) => "0x" + n.toString(16).padStart(40, "0");
const word = (addr) => "0x" + addr.slice(2).padStart(64, "0");
const uint = (n) => "0x" + n.toString(16).padStart(64, "0");
const addrArray = (xs) => "0x" + uint(32).slice(2) + uint(xs.length).slice(2) + xs.map((x) => word(x).slice(2)).join("");
const IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
const CODE = "0x6080604052";

// chain: { code: {addr: hex}, storage: {addr: {slot: word}}, calls: {addr: {selector: result}} }
function fakeRpc(chain, { failCalls = false } = {}) {
  return async (method, params) => {
    if (method === "eth_getCode") return chain.code[params[0]] || "0x";
    if (method === "eth_getStorageAt") return (chain.storage[params[0]] || {})[params[1]] || uint(0);
    if (method === "eth_call") {
      if (failCalls) throw new Error("eth_call: HTTP 429");
      const r = (chain.calls[params[0].to] || {})[params[0].data];
      if (r === undefined) throw new Error("execution reverted");
      return r;
    }
    throw new Error(`unexpected ${method}`);
  };
}
const sourcify = (map) => async (url) => ({ ok: true, json: async () => ({ match: map[url.split("/").pop()] ?? null }) });
const flags = (r) => r.flags.map((f) => f.id);

const PROXY = A(0x100), IMPL = A(0x200), PROXY_ADMIN = A(0x300), SAFE = A(0x400), KEY = A(0x500), TIMELOCK = A(0x600), BEACON = A(0x700);

test("transparent proxy whose ProxyAdmin is owned by one key: high", async () => {
  const rpc = fakeRpc({
    code: { [PROXY]: CODE, [IMPL]: CODE, [PROXY_ADMIN]: CODE },
    storage: { [PROXY]: { [IMPL_SLOT]: word(IMPL), [ADMIN_SLOT]: word(PROXY_ADMIN) } },
    calls: { [PROXY_ADMIN]: { "0x8da5cb5b": word(KEY) } },
  });
  const r = await inspectContract(PROXY, { rpc, fetchImpl: sourcify({ [PROXY]: "exact_match", [IMPL]: "exact_match" }) });
  assert.equal(r.proxy.kind, "transparent");
  assert.equal(r.implementation, IMPL);
  assert.equal(r.upgradeController.kind, "owned-contract");
  assert.equal(r.upgradeController.ownedBy.kind, "single-key");
  assert.deepEqual(flags(r), ["single-key-upgrade"]);
});

test("a Safe controller is read (threshold, owners); 1-of-N is high, N-of-M is not", async () => {
  const chain = (threshold) => fakeRpc({
    code: { [PROXY]: CODE, [SAFE]: CODE },
    storage: { [PROXY]: { [IMPL_SLOT]: word(IMPL), [ADMIN_SLOT]: word(SAFE) } },
    calls: { [SAFE]: { "0xe75235b8": uint(threshold), "0xa0e67e2b": addrArray([A(1), A(2), A(3)]) } },
  });
  const ok = await inspectContract(PROXY, { rpc: chain(2), fetchImpl: sourcify({ [PROXY]: "match", [IMPL]: "match" }) });
  assert.deepEqual([ok.upgradeController.kind, ok.upgradeController.threshold, ok.upgradeController.owners], ["safe", 2, 3]);
  assert.deepEqual(flags(ok), ["no-upgrade-delay"]);
  const weak = await inspectContract(PROXY, { rpc: chain(1), fetchImpl: sourcify({ [PROXY]: "match", [IMPL]: "match" }) });
  assert.deepEqual(flags(weak), ["safe-1-of-n"]);
});

test("UUPS behind a timelock; an unverified implementation is flagged", async () => {
  const rpc = fakeRpc({
    code: { [PROXY]: CODE, [TIMELOCK]: CODE },
    storage: { [PROXY]: { [IMPL_SLOT]: word(IMPL) } },
    calls: { [PROXY]: { "0x8da5cb5b": word(TIMELOCK) }, [TIMELOCK]: { "0xf27a0c92": uint(86400) } },
  });
  const r = await inspectContract(PROXY, { rpc, fetchImpl: sourcify({ [PROXY]: "exact_match", [IMPL]: null }) });
  assert.equal(r.proxy.kind, "uups");
  assert.equal(r.upgradeController.kind, "timelock");
  assert.match(r.upgradeController.text, /24 h/);
  assert.deepEqual(flags(r), ["unverified-implementation"]);
});

test("beacon proxy: the beacon's owner is the controller", async () => {
  const rpc = fakeRpc({
    code: { [PROXY]: CODE, [BEACON]: CODE },
    storage: { [PROXY]: { [BEACON_SLOT]: word(BEACON) } },
    calls: { [BEACON]: { "0x5c60da1b": word(IMPL), "0x8da5cb5b": word(KEY) } },
  });
  const r = await inspectContract(PROXY, { rpc, fetchImpl: sourcify({}) });
  assert.equal(r.proxy.kind, "beacon");
  assert.equal(r.implementation, IMPL);
  assert.ok(flags(r).includes("single-key-upgrade"));
});

test("a clone is fixed forever; a plain contract with a single-key owner is medium", async () => {
  const clone = "0x363d3d373d3d3d363d73" + IMPL.slice(2) + "5af43d82803e903d91602b57fd5bf3";
  const r1 = await inspectContract(PROXY, { rpc: fakeRpc({ code: { [PROXY]: clone }, storage: {}, calls: {} }), fetchImpl: sourcify({ [PROXY]: "match", [IMPL]: "match" }) });
  assert.equal(r1.proxy.kind, "eip1167-clone");
  assert.deepEqual(flags(r1), []);
  const r2 = await inspectContract(PROXY, { rpc: fakeRpc({ code: { [PROXY]: CODE }, storage: {}, calls: { [PROXY]: { "0x8da5cb5b": word(KEY) } } }), fetchImpl: sourcify({ [PROXY]: "match" }) });
  assert.equal(r2.proxy, null);
  assert.deepEqual(flags(r2), ["single-key-owner"]);
});

test("EIP-7702 account, no code, and the key behind 7702 counts as one key", async () => {
  const delegated = "0xef0100" + IMPL.slice(2);
  const r = await inspectContract(PROXY, { rpc: fakeRpc({ code: { [PROXY]: delegated }, storage: {}, calls: {} }), fetchImpl: sourcify({}) });
  assert.equal(r.proxy.kind, "eip7702");
  assert.ok(flags(r).includes("eoa-delegated"));
  const none = await inspectContract(KEY, { rpc: fakeRpc({ code: {}, storage: {}, calls: {} }), fetchImpl: sourcify({}) });
  assert.equal(none.isContract, false);
  const c = await classify(KEY, fakeRpc({ code: { [KEY]: delegated }, storage: {}, calls: {} }));
  assert.equal(c.kind, "single-key");
});

test("a rate-limited eth_call is an error, never read as 'no such function'", async () => {
  const rpc = fakeRpc({ code: { [PROXY]: CODE, [SAFE]: CODE }, storage: { [PROXY]: { [IMPL_SLOT]: word(IMPL), [ADMIN_SLOT]: word(SAFE) } }, calls: {} }, { failCalls: true });
  await assert.rejects(inspectContract(PROXY, { rpc, fetchImpl: sourcify({}) }), /429/);
  assert.equal(isAddress(PROXY), true);
  assert.equal(isAddress("0x123"), false);
});
