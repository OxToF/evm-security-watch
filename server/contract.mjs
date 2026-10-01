// Who can change a deployed EVM contract, and whether its code is public.
// Read-only RPC calls plus Sourcify (no key, Base and Robinhood Chain included).
//
// A proxy's code is whatever its controller points it at, so the question is who
// that controller is, followed to the end: a ProxyAdmin is a contract, its owner is
// what matters. An address with no code is one private key; a Safe has a threshold;
// a timelock has a delay.

const SLOTS = {
  eip1967Impl: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
  eip1967Admin: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
  eip1967Beacon: "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
  // AdminUpgradeabilityProxy before EIP-1967 (USDC's FiatTokenProxy among others).
  zosImpl: "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
  zosAdmin: "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b",
};
const SEL = {
  owner: "0x8da5cb5b",
  implementation: "0x5c60da1b",
  admin: "0xf851a440",
  getThreshold: "0xe75235b8",
  getOwners: "0xa0e67e2b",
  getMinDelay: "0xf27a0c92",
  facets: "0x7a0ed627",
};
export const CHAINS = { base: 8453, robinhood: 4663 };
const SOURCIFY = process.env.SOURCIFY_URL || "https://sourcify.dev/server/v2/contract";
const ZERO = "0x0000000000000000000000000000000000000000";

const duration = (sec) => (sec % 3600 === 0 ? `${sec / 3600} h` : sec % 60 === 0 ? `${sec / 60} min` : `${sec} s`);
export const isAddress = (a) => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a);
const wordToAddress = (w) => (w && w.length >= 66 ? "0x" + w.slice(-40).toLowerCase() : null);
const nonZero = (a) => (a && a !== ZERO ? a : null);

// A revert means "no such function here". Anything else (rate limit, timeout) is
// not an answer and must not be read as one: it propagates, and nothing is charged.
async function call(rpc, to, data) {
  try {
    const r = await rpc("eth_call", [{ to, data }, "latest"]);
    return r && r !== "0x" ? r : null;
  } catch (e) {
    if (/revert|invalid opcode|out of gas/i.test(String(e && e.message))) return null;
    throw e;
  }
}
function decodeAddressArray(hex) {
  const h = hex.slice(2);
  if (h.length < 128) return null;
  const n = parseInt(h.slice(64, 128), 16);
  if (n > 1000 || h.length < 128 + n * 64) return null;
  return Array.from({ length: n }, (_, i) => "0x" + h.slice(128 + i * 64 + 24, 128 + (i + 1) * 64));
}

// What kind of thing holds a power: one key, a Safe, a timelock, or another contract.
export async function classify(addr, rpc, depth = 0) {
  const code = await rpc("eth_getCode", [addr, "latest"]);
  if (!code || code === "0x") return { address: addr, kind: "single-key", text: "An address with no code: one private key." };
  if (/^0xef0100[0-9a-f]{40}$/i.test(code))
    return { address: addr, kind: "single-key", eip7702: true, text: "A key-held account with EIP-7702 delegated code: still one private key." };
  const th = await call(rpc, addr, SEL.getThreshold);
  const ow = th && (await call(rpc, addr, SEL.getOwners));
  const owners = ow && decodeAddressArray(ow);
  if (th && owners) {
    const threshold = Number(BigInt(th));
    return { address: addr, kind: "safe", threshold, owners: owners.length, text: `Safe multisig: ${threshold} of ${owners.length} owners must sign.` };
  }
  const delay = await call(rpc, addr, SEL.getMinDelay);
  if (delay) {
    const minDelaySeconds = Number(BigInt(delay));
    return { address: addr, kind: "timelock", minDelaySeconds, text: minDelaySeconds ? `Timelock: changes wait ${duration(minDelaySeconds)} after they are scheduled.` : "Timelock with no delay: changes apply as soon as they are scheduled." };
  }
  // A contract that is itself owned (a ProxyAdmin): follow it once more.
  const own = depth < 2 && nonZero(wordToAddress(await call(rpc, addr, SEL.owner)));
  if (own) {
    const by = await classify(own, rpc, depth + 1);
    return { address: addr, kind: "owned-contract", ownedBy: by, text: `A contract owned by ${own}: ${by.text}` };
  }
  return { address: addr, kind: "contract", text: "A contract whose approval rules this check does not read." };
}
const finalController = (c) => (c && c.kind === "owned-contract" ? finalController(c.ownedBy) : c);

async function sourcify(chainId, addr, fetchImpl) {
  try {
    const r = await fetchImpl(`${SOURCIFY}/${chainId}/${addr}`);
    if (!r.ok) return null;
    const j = await r.json();
    return j.match || "none"; // exact_match | match | none
  } catch { return null; }
}

export async function inspectContract(address, { chain = "base", rpc, fetchImpl = globalThis.fetch }) {
  const chainId = CHAINS[chain];
  const addr = address.toLowerCase();
  const code = await rpc("eth_getCode", [addr, "latest"]);
  if (!code || code === "0x") return { address: addr, chain, isContract: false, flags: [{ severity: "high", id: "not-a-contract", text: `No contract code at this address on ${chain}.` }] };

  const out = { address: addr, chain, chainId, isContract: true, proxy: null, implementation: null, upgradeController: null, owner: null, verified: {}, flags: [] };
  const slot = async (s) => nonZero(wordToAddress(await rpc("eth_getStorageAt", [addr, s, "latest"])));

  if (/^0xef0100[0-9a-f]{40}$/i.test(code)) {
    out.proxy = { kind: "eip7702", text: "An externally owned account delegating to code (EIP-7702): its key holder controls it." };
    out.implementation = "0x" + code.slice(-40).toLowerCase();
  } else {
    const minimal = code.match(/^0x363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$/i);
    const impl1967 = await slot(SLOTS.eip1967Impl);
    const beacon = !impl1967 && (await slot(SLOTS.eip1967Beacon));
    const implZos = !impl1967 && !beacon && (await slot(SLOTS.zosImpl));
    if (minimal) {
      out.proxy = { kind: "eip1167-clone", text: "A minimal clone: its implementation is fixed forever." };
      out.implementation = "0x" + minimal[1].toLowerCase();
    } else if (beacon) {
      out.proxy = { kind: "beacon", beacon, text: "A beacon proxy: whoever controls the beacon changes the code of every proxy behind it." };
      out.implementation = nonZero(wordToAddress(await call(rpc, beacon, SEL.implementation)));
      const bo = nonZero(wordToAddress(await call(rpc, beacon, SEL.owner)));
      if (bo) out.upgradeController = await classify(bo, rpc);
    } else if (impl1967 || implZos) {
      out.implementation = impl1967 || implZos;
      const admin = await slot(impl1967 ? SLOTS.eip1967Admin : SLOTS.zosAdmin);
      if (admin) {
        out.proxy = { kind: impl1967 ? "transparent" : "transparent-legacy", text: "A transparent proxy: its admin can point it at new code." };
        out.upgradeController = await classify(admin, rpc);
      } else {
        out.proxy = { kind: "uups", text: "A UUPS proxy: the upgrade check lives in the implementation, usually behind owner() or a role." };
        const o = nonZero(wordToAddress(await call(rpc, addr, SEL.owner)));
        if (o) out.upgradeController = { ...(await classify(o, rpc)), assumed: "owner() of the proxy; the implementation may gate upgrades on a role instead" };
      }
    } else if (await call(rpc, addr, SEL.facets)) {
      out.proxy = { kind: "diamond", text: "An EIP-2535 diamond: facets can be added or replaced by its owner." };
      const o = nonZero(wordToAddress(await call(rpc, addr, SEL.owner)));
      if (o) out.upgradeController = await classify(o, rpc);
    }
  }

  // A privileged owner, beyond upgrades (pause, mint, fees…). Read through the proxy.
  const o = nonZero(wordToAddress(await call(rpc, addr, SEL.owner)));
  if (o) out.owner = out.upgradeController && out.upgradeController.address === o ? out.upgradeController : await classify(o, rpc);

  if (chainId) {
    out.verified.contract = await sourcify(chainId, addr, fetchImpl);
    if (out.implementation) out.verified.implementation = await sourcify(chainId, out.implementation, fetchImpl);
  }

  // Flags.
  const upgradeable = out.proxy && !["eip1167-clone"].includes(out.proxy.kind);
  const fin = finalController(out.upgradeController);
  if (out.proxy && out.proxy.kind === "eip7702")
    out.flags.push({ severity: "high", id: "eoa-delegated", text: "This is a key-held account running delegated code: the key holder can change or bypass it at will." });
  if (upgradeable && fin && fin.kind === "single-key")
    out.flags.push({ severity: "high", id: "single-key-upgrade", text: `One private key (${fin.address}) can replace this contract's code at any time.` });
  if (upgradeable && fin && fin.kind === "safe" && fin.threshold === 1)
    out.flags.push({ severity: "high", id: "safe-1-of-n", text: `The upgrade Safe needs 1 of ${fin.owners} signatures: any single owner can replace the code.` });
  if (upgradeable && fin && fin.kind === "timelock" && fin.minDelaySeconds === 0)
    out.flags.push({ severity: "medium", id: "timelock-zero-delay", text: "The upgrade timelock has no delay." });
  if (upgradeable && fin && fin.kind === "safe" && fin.threshold > 1)
    out.flags.push({ severity: "info", id: "no-upgrade-delay", text: "An upgrade signed by the Safe takes effect immediately: there is no timelock in front of it." });
  if (upgradeable && !fin && out.proxy.kind !== "eip7702")
    out.flags.push({ severity: "medium", id: "upgrade-controller-unknown", text: "Upgradeable, but who can upgrade could not be read." });
  const ownerFin = finalController(out.owner);
  if (ownerFin && ownerFin.kind === "single-key" && !(upgradeable && fin && fin.kind === "single-key"))
    out.flags.push({ severity: "medium", id: "single-key-owner", text: `owner() is one private key (${ownerFin.address}); what it may do depends on the contract.` });
  if (out.verified.implementation === "none")
    out.flags.push({ severity: "medium", id: "unverified-implementation", text: `The live implementation ${out.implementation} has no verified source on Sourcify.` });
  if (out.verified.contract === "none")
    out.flags.push({ severity: out.implementation ? "low" : "medium", id: "unverified-contract", text: "This address has no verified source on Sourcify." });

  const order = { high: 0, medium: 1, low: 2, info: 3 };
  out.flags.sort((a, b) => order[a.severity] - order[b.severity]);
  return out;
}
