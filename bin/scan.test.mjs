// node --test bin/scan.test.mjs — offline: every network call goes through a fake fetch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseGitmodules, parseSoldeerLock, pragmaExcludes08, pragmaAllows, isTestOrScript,
  npmRepoMatches, resolveSubmodules, productionImports, readRemappings,
} from "./deps.mjs";
import { triageAdvisories } from "./scan.mjs";

const json = (body, ok = true) => ({ ok, json: async () => body });

test("pragma: only a range no 0.8 compiler can build is flagged", () => {
  for (const r of ["0.5.16", "=0.5.16", "^0.7.0", "0.6.12", ">=0.5.0 <0.8.0", "~0.7.6"]) assert.equal(pragmaExcludes08(r), true, r);
  for (const r of [">=0.5.0", "^0.8.0", "0.8.19", ">=0.7.0 <0.9.0", "^0.7.0 || ^0.8.0", ">=0.8.0"]) assert.equal(pragmaExcludes08(r), false, r);
  assert.equal(pragmaAllows("^0.8.4", "0.8.3"), false);
  assert.equal(pragmaAllows("^0.8.4", "0.8.30"), true);
});

test("tests, scripts and mocks are not production code", () => {
  for (const f of ["test/Foo.t.sol", "src/test/Helper.sol", "script/Deploy.s.sol", "contracts/mocks/MockERC20.sol", "src/Foo.t.sol"]) assert.equal(isTestOrScript(f), true, f);
  for (const f of ["src/Vault.sol", "contracts/Pool.sol", "src/libraries/Math.sol"]) assert.equal(isTestOrScript(f), false, f);
});

test("gitmodules and soldeer.lock parse", () => {
  const g = parseGitmodules(`[submodule "lib/openzeppelin-contracts"]\n\tpath = lib/openzeppelin-contracts\n\turl = https://github.com/OpenZeppelin/openzeppelin-contracts\n[submodule "lib/forge-std"]\n\tpath = lib/forge-std\n\turl = https://github.com/foundry-rs/forge-std`);
  assert.deepEqual(g.map((s) => s.path), ["lib/openzeppelin-contracts", "lib/forge-std"]);
  const s = parseSoldeerLock(`[[dependencies]]\nname = "@openzeppelin-contracts"\nversion = "5.0.2"\nurl = "x"\n\n[[dependencies]]\nname = "forge-std"\nversion = "1.9.1"\n`);
  assert.deepEqual(s.map((d) => [d.name, d.version]), [["@openzeppelin/contracts", "5.0.2"], ["forge-std", "1.9.1"]]);
});

test("an npm name only counts when the npm package points back at the same repo", async () => {
  const reg = {
    "https://registry.npmjs.org/@openzeppelin%2Fcontracts/latest": json({ repository: { url: "git+https://github.com/OpenZeppelin/openzeppelin-contracts.git" } }),
    // Squatted name: exists on npm, but published from somewhere else.
    "https://registry.npmjs.org/forge-std/latest": json({ repository: { url: "git+https://github.com/shunkakinoki/contracts.git" } }),
    "https://registry.npmjs.org/shorthand/latest": json({ repository: "github:acme/lib" }),
  };
  const f = async (u) => reg[u] || json("Not found", false);
  assert.equal(await npmRepoMatches("@openzeppelin/contracts", { owner: "OpenZeppelin", repo: "openzeppelin-contracts" }, f), true);
  assert.equal(await npmRepoMatches("forge-std", { owner: "foundry-rs", repo: "forge-std" }, f), false);
  assert.equal(await npmRepoMatches("ethereum-vault-connector", { owner: "euler-xyz", repo: "ethereum-vault-connector" }, f), false);
  assert.equal(await npmRepoMatches("shorthand", { owner: "acme", repo: "lib" }, f), true);
});

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "evm-fixture-"));
  const w = (p, t) => { mkdirSync(join(dir, p, ".."), { recursive: true }); writeFileSync(join(dir, p), t); };
  w(".gitmodules", `[submodule "lib/openzeppelin-contracts"]\n\tpath = lib/openzeppelin-contracts\n\turl = https://github.com/OpenZeppelin/openzeppelin-contracts\n[submodule "lib/forge-std"]\n\tpath = lib/forge-std\n\turl = https://github.com/foundry-rs/forge-std\n[submodule "lib/evc"]\n\tpath = lib/evc\n\turl = https://github.com/euler-xyz/ethereum-vault-connector\n`);
  w("remappings.txt", "@openzeppelin/=lib/openzeppelin-contracts/\nforge-std/=lib/forge-std/src/\n");
  w("src/Vault.sol", `pragma solidity ^0.8.0;\nimport {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";\nimport "./Lib.sol";\n`);
  w("test/Vault.t.sol", `pragma solidity ^0.8.0;\nimport "forge-std/Test.sol";\nimport "ethereum-vault-connector/EVC.sol";\n`);
  return dir;
}

test("submodules resolve through the git tree, the pinned manifest and the npm repo check", async () => {
  const dir = fixture();
  const routes = {
    "https://api.github.com/repos/acme/vault/git/trees/HEAD?recursive=1": json({ tree: [
      { path: "lib/openzeppelin-contracts", type: "commit", sha: "a".repeat(40) },
      { path: "lib/forge-std", type: "commit", sha: "b".repeat(40) },
      { path: "lib/evc", type: "commit", sha: "c".repeat(40) },
      { path: "src/Vault.sol", type: "blob", sha: "d".repeat(40) },
    ] }),
    [`https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/${"a".repeat(40)}/package.json`]: json({ name: "openzeppelin-solidity", version: "5.0.2" }),
    [`https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/${"a".repeat(40)}/contracts/package.json`]: json({ name: "@openzeppelin/contracts", version: "5.0.2" }),
    [`https://raw.githubusercontent.com/foundry-rs/forge-std/${"b".repeat(40)}/package.json`]: json({ name: "forge-std", version: "1.9.1" }),
    [`https://raw.githubusercontent.com/euler-xyz/ethereum-vault-connector/${"c".repeat(40)}/package.json`]: json({ name: "ethereum-vault-connector", version: "1.0.0" }),
    "https://registry.npmjs.org/@openzeppelin%2Fcontracts/latest": json({ repository: { url: "git+https://github.com/OpenZeppelin/openzeppelin-contracts.git" } }),
    "https://registry.npmjs.org/forge-std/latest": json({ repository: { url: "git+https://github.com/shunkakinoki/contracts.git" } }),
  };
  const f = async (u) => routes[u] || json(null, false);
  const subs = await resolveSubmodules(dir, { owner: "acme", repo: "vault" }, { fetchImpl: f });
  const by = Object.fromEntries(subs.map((d) => [d.path, d]));
  assert.equal(by["lib/openzeppelin-contracts"].status, "resolved");
  assert.equal(by["lib/openzeppelin-contracts"].name, "@openzeppelin/contracts");
  assert.equal(by["lib/forge-std"].status, "unresolved");
  assert.equal(by["lib/evc"].status, "unresolved");
  assert.match(by["lib/evc"].reason, /not published on npm/);

  // Production code imports OZ (through a remapping); only tests import forge-std.
  const used = productionImports(dir, [join(dir, "src/Vault.sol"), join(dir, "test/Vault.t.sol")], readRemappings(dir), subs.map((d) => d.path));
  assert.equal(used.has("lib/openzeppelin-contracts"), true);
  assert.equal(used.has("lib/forge-std"), false);
});

test("triage: libraries production imports are on-chain, the rest is toolchain", () => {
  const adv = [
    { id: "A", packages: ["@openzeppelin/contracts 4.7.0"] },
    { id: "B", packages: ["hardhat 2.0.0"] },
    { id: "C", packages: ["forge-std 1.0.0"] },
  ];
  const { onchain, toolchain } = triageAdvisories(adv, new Set(["@openzeppelin/contracts", "forge-std"]));
  assert.deepEqual(onchain.map((a) => a.id), ["A"]);
  assert.deepEqual(toolchain.map((a) => a.id), ["B", "C"]);
});

test("verified sources without a manifest: imported libraries are 'not checked', never 'no external library'", async () => {
  const { runScan } = await import("./scan.mjs");
  const dir = mkdtempSync(join(tmpdir(), "evm-nomanifest-"));
  const w = (p, t) => { mkdirSync(join(dir, p, ".."), { recursive: true }); writeFileSync(join(dir, p), t); };
  w("src/core/Token.sol", `pragma solidity ^0.8.20;\nimport {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";\nimport {Errors} from "src/core/Errors.sol";\n`);
  w("src/core/Errors.sol", "pragma solidity ^0.8.20;\n");
  w("lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol", "pragma solidity ^0.8.20;\n");
  const r = await runScan({ localPath: dir, out: join(dir, "_out"), log: () => {}, fetchImpl: async () => { throw new Error("no network in this test"); } });
  assert.equal(r.deps.coverage.noExternalImports, false);
  assert.deepEqual(r.deps.coverage.unresolved.map((u) => u.path), ["@openzeppelin/contracts"]);
  const md = (await import("node:fs")).readFileSync(r.mdPath, "utf8");
  assert.match(md, /Not checked/);
  assert.doesNotMatch(md, /import no external library/);
});

test("fix links appear only when a contact is given, pre-filled with the repo and reference", async () => {
  const { fixMailto } = await import("./scan.mjs");
  const meta = { owner: "acme", repo: "vault" };
  assert.equal(fixMailto(null, meta, "x"), null);
  assert.equal(fixMailto({ contact: null }, meta, "x"), null);
  const l = decodeURIComponent(fixMailto({ contact: "ops@example.com", ref: "job-1" }, meta, "Fix request: acme/vault: GHSA-1", ["Advisory: GHSA-1"]));
  assert.match(l, /^mailto:ops@example\.com\?subject=Fix request: acme\/vault: GHSA-1&body=/);
  assert.match(l, /Repository: https:\/\/github\.com\/acme\/vault/);
  assert.match(l, /Scan reference: job-1/);
});
