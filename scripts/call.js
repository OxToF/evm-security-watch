#!/usr/bin/env node
// EVM Security Watch — small eth_call / selector / getCode recon tool (Base Sepolia by default).
// Usage:
//   node call.js sel "getInstalledPlugins()"                 -> print the 4-byte selector
//   node call.js call <addr> "getInstalledPlugins()"         -> eth_call (no args), returns raw
//   node call.js call <addr> "isOwner(address)" <argHex32>   -> eth_call with raw concatenated args
//   node call.js code <addr>                                 -> deployed bytecode size (eth_getCode)
//   node call.js codehash <addr>                             -> keccak256 of the runtime bytecode (for diffing)
//   node call.js storage <addr> <slot>                       -> eth_getStorageAt
// RPC override: EVM_RPC=... node call.js ...
const { keccak256 } = require("js-sha3");
const https = require("https");
const RPC = process.env.EVM_RPC || "https://sepolia.base.org";

function selector(sig) { return "0x" + keccak256(sig).slice(0, 8); }
function keccakHex(hexNo0x) {
  const bytes = Buffer.from(hexNo0x, "hex");
  return "0x" + keccak256(bytes);
}
function rpc(method, params) {
  return new Promise((res, rej) => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
    const req = https.request(RPC, { method: "POST", headers: { "content-type": "application/json" } }, r => {
      let b = ""; r.on("data", d => b += d); r.on("end", () => {
        try { const j = JSON.parse(b); j.error ? rej(j.error) : res(j.result); } catch (e) { rej(b); }
      });
    });
    req.on("error", rej); req.write(body); req.end();
  });
}
// decode ABI address[] (offset, length, then 32-byte words)
function decodeAddressArray(hex) {
  const h = hex.replace(/^0x/, "");
  if (h.length < 128) return [];
  const len = parseInt(h.slice(64, 128), 16);
  const out = [];
  for (let i = 0; i < len; i++) {
    const word = h.slice(128 + i * 64, 128 + i * 64 + 64);
    out.push("0x" + word.slice(24));
  }
  return out;
}

(async () => {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "sel") { console.log(selector(rest[0])); return; }
  if (cmd === "call") {
    const [addr, sig, ...args] = rest;
    const data = selector(sig) + args.map(a => a.replace(/^0x/, "").padStart(64, "0")).join("");
    const raw = await rpc("eth_call", [{ to: addr, data }, "latest"]);
    console.log("raw:", raw);
    if (sig.includes("[]") || sig.startsWith("getInstalledPlugins")) {
      console.log("addresses:", decodeAddressArray(raw));
    }
    return;
  }
  if (cmd === "code") {
    const code = await rpc("eth_getCode", [rest[0], "latest"]);
    console.log("bytes:", (code.length - 2) / 2, "isContract:", code !== "0x");
    return;
  }
  if (cmd === "codehash") {
    const code = await rpc("eth_getCode", [rest[0], "latest"]);
    console.log("len:", (code.length - 2) / 2, "keccak:", keccakHex(code.replace(/^0x/, "")));
    return;
  }
  if (cmd === "storage") {
    console.log(await rpc("eth_getStorageAt", [rest[0], rest[1], "latest"]));
    return;
  }
  console.log("unknown command. see the file header.");
})();
