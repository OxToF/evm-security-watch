// On-chain verification of a USDG payment on Robinhood Chain. Given a transaction
// hash, confirm through JSON-RPC that it succeeded and emitted an ERC-20 Transfer
// of EXACTLY the job's amount of USDG to the merchant, in a block mined after the
// job was quoted. Zero deps: plain fetch to an EVM RPC.
//
// Why exact: an EVM transfer carries no memo, and a tx hash is public the moment
// it lands. Each job is quoted a unique amount (price + a few micro-USDG), so a
// payment can only be claimed by the job it was made for. Reading logs rather
// than tx.to/input also accepts payments sent through a smart wallet.

// Canonical USDG on Robinhood Chain (docs.robinhood.com/chain/contracts and
// docs.paxos.com). Dozens of fake "Global Dollar (USDG)" tokens exist on the
// chain: only this address counts, never the ticker.
export const USDG = {
  address: "0x5fc5360d0400a0fd4f2af552add042d716f1d168",
  decimals: 6,
  symbol: "USDG",
  chainId: 4663,
  network: "robinhood",
};
export const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const lc = (s) => String(s || "").toLowerCase();
const topicAddress = (t) => "0x" + lc(t).slice(-40);

// Pure check on a receipt + its block, exported for tests (no network).
export function verifyFromReceipt(receipt, block, { amount, merchant, token = USDG.address, notBefore = 0 }) {
  if (!receipt) return { ok: false, reason: "transaction not found or not yet mined" };
  if (receipt.status !== "0x1") return { ok: false, reason: "transaction reverted" };
  const want = BigInt(amount);
  const transfers = (receipt.logs || []).filter((l) =>
    !l.removed && lc(l.address) === lc(token) && l.topics && l.topics.length === 3 &&
    lc(l.topics[0]) === TRANSFER_TOPIC && topicAddress(l.topics[2]) === lc(merchant));
  if (!transfers.length) return { ok: false, reason: "no USDG transfer to the merchant in this transaction" };
  const values = transfers.map((l) => BigInt(l.data));
  if (!values.includes(want)) {
    return { ok: false, reason: `USDG sent to the merchant (${values.join(", ")} base units) does not equal the quoted amount (${want}); each quote has a unique amount` };
  }
  if (notBefore) {
    const ts = block && block.timestamp ? Number(BigInt(block.timestamp)) * 1000 : 0;
    // Two minutes of slack for clock skew between us and the sequencer.
    if (!ts || ts < notBefore - 120_000) return { ok: false, reason: "payment was made before this job was quoted" };
  }
  const from = topicAddress(transfers[values.indexOf(want)].topics[1]);
  return { ok: true, received: want.toString(), from, block: receipt.blockNumber };
}

async function rpc(url, method, params, fetchImpl) {
  const res = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`RPC ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`RPC error: ${body.error.message}`);
  return body.result;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function verifyUsdgPayment({
  txHash, amount, merchant, rpcUrl, notBefore = 0, token = USDG.address, chainId = USDG.chainId,
  fetchImpl = globalThis.fetch, retries = 10, delayMs = 3000,
}) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHash || "")) return { ok: false, reason: "invalid transaction hash" };
  // A mis-pointed RPC (another chain) would happily return "not found" forever,
  // or worse, a receipt from a chain where the same address means nothing.
  try {
    const id = Number(BigInt(await rpc(rpcUrl, "eth_chainId", [], fetchImpl)));
    if (id !== chainId) return { ok: false, reason: `RPC is on chain ${id}, expected ${chainId}` };
  } catch (e) {
    return { ok: false, reason: `RPC lookup failed: ${e.message}` };
  }
  // The client calls us right after sending, so the receipt may not exist yet.
  let receipt = null, lastErr = null;
  for (let i = 0; i < retries; i++) {
    try { receipt = await rpc(rpcUrl, "eth_getTransactionReceipt", [txHash], fetchImpl); }
    catch (e) { lastErr = e; }
    if (receipt) break;
    if (i < retries - 1) await sleep(delayMs);
  }
  if (!receipt && lastErr) return { ok: false, reason: `RPC lookup failed: ${lastErr.message}` };
  let block = null;
  if (receipt && notBefore) {
    try { block = await rpc(rpcUrl, "eth_getBlockByNumber", [receipt.blockNumber, false], fetchImpl); }
    catch (e) { return { ok: false, reason: `RPC lookup failed: ${e.message}` }; }
  }
  return verifyFromReceipt(receipt, block, { amount, merchant, token, notBefore });
}

// Base units <-> display, without floats.
export const toBase = (usd) => BigInt(Math.round(Number(usd) * 10 ** USDG.decimals));
export function formatUnits(base) {
  const b = BigInt(base), d = 10n ** BigInt(USDG.decimals);
  return `${b / d}.${(b % d).toString().padStart(USDG.decimals, "0")}`;
}
