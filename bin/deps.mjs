// Dependency discovery for Solidity repos. npm lockfiles cover Hardhat projects,
// but most Foundry projects vendor their libraries as git submodules under lib/
// (or through Soldeer), which no lockfile lists. A GitHub tarball ships those
// submodule directories empty, so the pinned commit is read from the git tree
// and the version from that commit's package.json.
//
// Every dependency ends up in exactly one place: resolved to an npm name@version
// (checked against OSV), or listed as unresolved, so the report can say
// "not checked" instead of implying "clean".

import { readFileSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

// Soldeer names its packages after the npm ones with the slash flattened.
const SOLDEER_TO_NPM = {
  "@openzeppelin-contracts": "@openzeppelin/contracts",
  "@openzeppelin-contracts-upgradeable": "@openzeppelin/contracts-upgradeable",
  "@uniswap-v3-core": "@uniswap/v3-core",
  "@uniswap-v3-periphery": "@uniswap/v3-periphery",
  "@uniswap-v2-core": "@uniswap/v2-core",
  "@chainlink-contracts": "@chainlink/contracts",
  "@aave-core-v3": "@aave/core-v3",
  solmate: "solmate",
  solady: "solady",
  "forge-std": "forge-std",
};

// Libraries that only ever run in tests or scripts, never in a deployed contract.
export const TEST_ONLY_PACKAGES = new Set(["forge-std", "ds-test", "@std/forge-std", "halmos-cheatcodes", "erc4626-tests"]);

export function parseGitmodules(text) {
  const out = [];
  let cur = null;
  for (const line of String(text).split("\n")) {
    if (/^\s*\[submodule\s+"[^"]*"\]/.test(line)) { cur = {}; out.push(cur); continue; }
    const m = line.match(/^\s*(path|url|branch)\s*=\s*(.+?)\s*$/);
    if (m && cur) cur[m[1]] = m[2];
  }
  return out.filter((s) => s.path && s.url);
}

export function githubSlug(url) {
  const m = String(url).match(/github\.com[/:]([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/);
  return m ? { owner: m[1], repo: m[2] } : null;
}

// soldeer.lock: TOML [[dependencies]] blocks with name / version.
export function parseSoldeerLock(text) {
  const out = [];
  let cur = null;
  for (const line of String(text).split("\n")) {
    if (/^\s*\[\[dependencies\]\]/.test(line)) { cur = {}; out.push(cur); continue; }
    const m = line.match(/^\s*(name|version)\s*=\s*"([^"]+)"/);
    if (m && cur) cur[m[1]] = m[2];
  }
  return out.filter((d) => d.name && d.version).map((d) => ({ name: SOLDEER_TO_NPM[d.name] || d.name, version: d.version, source: "soldeer", soldeerName: d.name }));
}

// Remappings from remappings.txt and foundry.toml: "prefix=target".
export function readRemappings(dir) {
  const out = [];
  const add = (s) => { const i = s.indexOf("="); if (i > 0) out.push({ from: s.slice(0, i).trim(), to: s.slice(i + 1).trim() }); };
  const rt = join(dir, "remappings.txt");
  if (existsSync(rt)) for (const l of readFileSync(rt, "utf8").split("\n")) if (l.trim() && !l.trim().startsWith("#")) add(l.trim());
  const ft = join(dir, "foundry.toml");
  if (existsSync(ft)) {
    const m = readFileSync(ft, "utf8").match(/remappings\s*=\s*\[([\s\S]*?)\]/);
    if (m) for (const s of m[1].matchAll(/"([^"]+)"/g)) add(s[1]);
  }
  return out;
}

// One API call for the whole tree: submodules are the entries of type "commit".
async function submoduleCommits(owner, repo, fetchImpl, token) {
  const headers = { "User-Agent": "evm-security-watch", Accept: "application/vnd.github+json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetchImpl(`https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`, { headers });
  if (!res.ok) throw new Error(`GitHub tree ${res.status}`);
  const body = await res.json();
  const map = new Map();
  for (const e of body.tree || []) if (e.type === "commit") map.set(e.path, e.sha);
  return map;
}

// A package.json name is only a claim. "ethereum-vault-connector" on npm is a
// squatted malicious package that has nothing to do with Euler's GitHub repo of
// the same name, so matching on the name alone would report malware in Euler.
// Only trust the name when the npm package points back at the same repository.
export async function npmRepoMatches(name, slug, fetchImpl) {
  // /latest is small and, unlike the abbreviated install metadata, keeps `repository`.
  const res = await fetchImpl(`https://registry.npmjs.org/${name.replace("/", "%2F")}/latest`, { headers: { Accept: "application/json" } });
  if (!res.ok) return false;
  let body; try { body = await res.json(); } catch { return false; }
  const repo = body && body.repository && (body.repository.url || body.repository);
  const raw = String(repo || "").replace(/^git\+/, "").replace(/#.*$/, "").replace(/^github:/, "");
  const got = githubSlug(raw) || (/^[\w.-]+\/[\w.-]+$/.test(raw) ? { owner: raw.split("/")[0], repo: raw.split("/")[1].replace(/\.git$/, "") } : null);
  return !!got && got.owner.toLowerCase() === slug.owner.toLowerCase() && got.repo.toLowerCase() === slug.repo.toLowerCase();
}

// Where a Solidity repo keeps the manifest of the package it publishes: the root,
// or contracts/ for monorepos like OpenZeppelin (root is "openzeppelin-solidity").
const MANIFEST_PATHS = ["package.json", "contracts/package.json"];

async function packageJsonAt(slug, sha, fetchImpl, path = "package.json") {
  const res = await fetchImpl(`https://raw.githubusercontent.com/${slug.owner}/${slug.repo}/${sha}/${path}`, { headers: { "User-Agent": "evm-security-watch" } });
  if (!res.ok) return null;
  try { return await res.json(); } catch { return null; }
}

// Resolve top-level submodules to npm name@version. `meta` is {owner, repo} of the
// scanned repo (null for a local path, in which case submodules are unresolved).
export async function resolveSubmodules(dir, meta, { fetchImpl = globalThis.fetch, token = null, log = () => {} } = {}) {
  const gm = join(dir, ".gitmodules");
  if (!existsSync(gm)) return [];
  const subs = parseGitmodules(readFileSync(gm, "utf8"));
  if (!subs.length) return [];
  let commits = new Map();
  if (meta) {
    try { commits = await submoduleCommits(meta.owner, meta.repo, fetchImpl, token); }
    catch (e) { log(`[scan] could not read submodule commits: ${e.message}`); }
  }
  const out = [];
  for (const s of subs) {
    const slug = githubSlug(s.url);
    const sha = commits.get(s.path) || null;
    const dep = { path: s.path, url: s.url, sha, name: null, version: null, source: "submodule", status: "unresolved", reason: null };
    if (!slug) dep.reason = "not hosted on GitHub";
    else if (!sha) dep.reason = "pinned commit not readable";
    else {
      const seen = [];
      for (const path of MANIFEST_PATHS) {
        const pkg = await packageJsonAt(slug, sha, fetchImpl, path);
        if (!pkg || !pkg.name || !pkg.version) continue;
        seen.push(pkg.name);
        if (await npmRepoMatches(pkg.name, slug, fetchImpl)) { Object.assign(dep, { name: pkg.name, version: pkg.version, status: "resolved" }); break; }
      }
      if (dep.status !== "resolved") dep.reason = seen.length
        ? `not published on npm from this repository (npm name ${seen.map((n) => `"${n}"`).join(" / ")} missing or owned by another project), so no advisory database covers it`
        : "no package.json at the pinned commit";
    }
    if (!dep.name) dep.name = slug ? `${slug.owner}/${slug.repo}` : s.path;
    out.push(dep);
  }
  log(`[scan] ${out.length} git submodule(s): ${out.filter((d) => d.status === "resolved").length} resolved to a package version`);
  return out;
}

// --- which packages reach deployed bytecode ----------------------------------

const TEST_DIR = /(^|\/)(test|tests|script|scripts|mocks?|certora|echidna|halmos|fuzz|invariants?)\//i;
export const isTestOrScript = (rel) => TEST_DIR.test(rel.replace(/\\/g, "/")) || /\.(t|s)\.sol$/.test(rel);

// Package root of an import path: "@scope/name/..." -> "@scope/name", "name/..." -> "name".
function importRoot(p) {
  const parts = p.split("/");
  return p.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

// Map every import in production .sol files to the dependency it comes from.
// Returns a Set of dependency keys: npm names, and submodule paths ("lib/x").
export function productionImports(dir, solFiles, remappings, submodulePaths) {
  const used = new Set();
  const subs = [...submodulePaths].sort((a, b) => b.length - a.length);
  for (const f of solFiles) {
    const rel = relative(dir, f);
    if (isTestOrScript(rel)) continue;
    let t; try { t = readFileSync(f, "utf8"); } catch { continue; }
    for (const m of t.matchAll(/^\s*import\s+(?:[^'"]*?\s+from\s+)?["']([^"']+)["']/gm)) {
      let p = m[1];
      if (p.startsWith(".")) continue;
      const r = remappings.filter((x) => p.startsWith(x.from)).sort((a, b) => b.from.length - a.from.length)[0];
      if (r) p = r.to.replace(/\/$/, "") + "/" + p.slice(r.from.length).replace(/^\//, "");
      p = p.replace(/^\.\//, "");
      const sub = subs.find((s) => p === s || p.startsWith(s + "/"));
      const sold = p.match(/^dependencies\/([^/]+?)-\d[^/]*\//); // Soldeer: dependencies/<name>-<version>/
      if (sub) used.add(sub);
      else if (sold) { used.add(sold[1]); if (SOLDEER_TO_NPM[sold[1]]) used.add(SOLDEER_TO_NPM[sold[1]]); }
      else if (p.startsWith("node_modules/")) used.add(importRoot(p.slice("node_modules/".length)));
      else if (p.startsWith("lib/")) used.add(p.split("/").slice(0, 2).join("/")); // vendored, no submodule entry
      else used.add(importRoot(p));
    }
  }
  return used;
}

// --- pragma: can this file be compiled with a 0.8.x compiler at all? ----------

function cmp(a, b) { for (let i = 0; i < 3; i++) { if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) - (b[i] || 0); } return 0; }
const ver = (s) => s.split(".").map((n) => parseInt(n, 10) || 0);

function satisfiesOne(v, c) {
  const m = c.match(/^(\^|~|>=|<=|>|<|=)?\s*v?(\d+(?:\.\d+){0,2})$/);
  if (!m) return true; // unknown syntax: do not accuse
  const op = m[1] || "=", t = ver(m[2]);
  const d = cmp(v, t);
  switch (op) {
    case "=": return d === 0 || (m[2].split(".").length < 3 && v.slice(0, m[2].split(".").length).every((x, i) => x === t[i]));
    case ">": return d > 0;
    case ">=": return d >= 0;
    case "<": return d < 0;
    case "<=": return d <= 0;
    case "~": return d >= 0 && v[0] === t[0] && v[1] === t[1];
    case "^": return d >= 0 && (t[0] > 0 ? v[0] === t[0] : t[1] > 0 ? v[0] === 0 && v[1] === t[1] : cmp(v, t) === 0);
  }
  return true;
}

export function pragmaAllows(range, version) {
  const v = ver(version);
  return String(range).split("||").some((alt) => {
    const cs = alt.trim().replace(/(\^|~|>=|<=|>|<|=)\s+/g, "$1").split(/\s+/).filter(Boolean);
    return cs.every((c) => satisfiesOne(v, c));
  });
}

// True when no 0.8.x compiler can build this pragma: the file compiles without
// built-in overflow checks. ">=0.5.0" is not that; "0.6.12" and "^0.7.0" are.
export function pragmaExcludes08(range) {
  for (let p = 0; p <= 40; p++) if (pragmaAllows(range, `0.8.${p}`)) return false;
  return true;
}

// The compiler the build actually uses, when the config pins one.
export function configuredSolc(dir) {
  const ft = join(dir, "foundry.toml");
  if (existsSync(ft)) {
    const m = readFileSync(ft, "utf8").match(/^\s*solc(?:_version)?\s*=\s*["']?([0-9.]+)["']?/m);
    if (m) return m[1];
  }
  for (const n of ["hardhat.config.ts", "hardhat.config.js", "hardhat.config.cjs"]) {
    const f = join(dir, n);
    if (existsSync(f)) {
      const m = readFileSync(f, "utf8").match(/version\s*:\s*["']([0-9]+\.[0-9]+\.[0-9]+)["']/);
      if (m) return m[1];
    }
  }
  return null;
}
