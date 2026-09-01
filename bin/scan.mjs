// `scan` — the per-repo product. Point it at a public GitHub Solidity repo and it
// produces the dated report a customer receives: (1) dependency advisories on the
// repo's EXACT pinned npm versions (OSV/GitHub Advisory DB), (2) build hygiene
// (Solidity pragma range, framework), and (3) code leads mapped to the 14-class
// EVM checklist. Deterministic and near-zero cost: OSV + local grep, no compiler.

import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { normalize } from "./collect.mjs";

const OSV_QUERY = "https://api.osv.dev/v1/query";

export function parseGithubUrl(input) {
  const m = String(input).trim().match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/);
  if (!m) throw new Error(`not a public https://github.com/<owner>/<repo> URL: ${input}`);
  return { owner: m[1], repo: m[2], url: `https://github.com/${m[1]}/${m[2]}.git` };
}

function cloneRepo(url, dir, log) {
  log(`[scan] cloning ${url}`);
  execFileSync("git", ["clone", "--depth", "1", "--quiet", url, dir], { stdio: ["ignore", "ignore", "pipe"], timeout: 120000 });
}

function findFiles(dir, predicate, skip = new Set(["node_modules", ".git", "out", "cache", "artifacts", "lib", "broadcast", "typechain-types"])) {
  const out = [];
  const walk = (d) => {
    let e; try { e = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const x of e) {
      if (x.isDirectory()) { if (!skip.has(x.name)) walk(join(d, x.name)); }
      else if (predicate(x.name)) out.push(join(d, x.name));
    }
  };
  walk(dir);
  return out;
}

// Extract {name, version} from package-lock.json (v1/v2/v3) or yarn.lock.
export function parsePackageLock(text) {
  const out = [];
  let json; try { json = JSON.parse(text); } catch { return out; }
  if (json.packages) { // lockfile v2/v3
    for (const [k, v] of Object.entries(json.packages)) {
      if (!k || !v || !v.version) continue;
      const idx = k.lastIndexOf("node_modules/");
      if (idx === -1) continue;
      out.push({ name: k.slice(idx + "node_modules/".length), version: v.version });
    }
  } else if (json.dependencies) { // lockfile v1
    const walk = (deps) => { for (const [name, v] of Object.entries(deps)) { if (v && v.version) out.push({ name, version: v.version }); if (v && v.dependencies) walk(v.dependencies); } };
    walk(json.dependencies);
  }
  return out;
}

export function parseYarnLock(text) {
  const out = [];
  const blocks = text.split(/\n(?=\S)/);
  for (const b of blocks) {
    const header = b.split("\n")[0];
    const vm = b.match(/\n\s+version:?\s+"?([^"\n]+)"?/);
    if (!vm) continue;
    const version = vm[1].trim();
    // header like: "@openzeppelin/contracts@^4.9.0", "@openzeppelin/contracts@4.9.3":
    for (const spec of header.split(",")) {
      const s = spec.trim().replace(/^"|":?$|"$/g, "");
      const at = s.lastIndexOf("@");
      if (at > 0) out.push({ name: s.slice(0, at), version });
    }
  }
  return out;
}

function readDeps(dir) {
  const locks = findFiles(dir, (n) => n === "package-lock.json" || n === "yarn.lock");
  let crates = [];
  for (const lf of locks) {
    const t = readFileSync(lf, "utf8");
    crates = crates.concat(lf.endsWith("yarn.lock") ? parseYarnLock(t) : parsePackageLock(t));
  }
  return crates;
}

async function scanDependencies(deps, fetchImpl, log) {
  const seen = new Set(), uniq = [];
  for (const c of deps) { const k = `${c.name}@${c.version}`; if (!seen.has(k)) { seen.add(k); uniq.push(c); } }
  log(`[scan] ${uniq.length} unique pinned npm packages -> querying OSV (version-filtered)`);
  const rawByPkg = []; let failures = 0;
  const CONC = 8;
  for (let i = 0; i < uniq.length; i += CONC) {
    const batch = uniq.slice(i, i + CONC);
    const results = await Promise.all(batch.map(async (c) => {
      try {
        const res = await fetchImpl(OSV_QUERY, { method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ package: { ecosystem: "npm", name: c.name }, version: c.version }) });
        if (!res.ok) return { c, vulns: null };
        return { c, vulns: (await res.json()).vulns || [] };
      } catch { return { c, vulns: null }; }
    }));
    for (const r of results) { if (r.vulns === null) failures++; else if (r.vulns.length) rawByPkg.push([`${r.c.name} ${r.c.version}`, r.vulns]); }
  }
  return { advisories: normalize(rawByPkg), failures };
}

// High-signal Solidity leads mapped to skill/vuln-classes.md. Leads, not findings.
const LEAD_PATTERNS = [
  { cls: "#1", label: "reentrancy: low-level value call", re: /\.call\{value:/ },
  { cls: "#2", label: "access control: tx.origin", re: /\btx\.origin\b/ },
  { cls: "#3", label: "proxy: delegatecall / upgrade auth", re: /\bdelegatecall\b|_authorizeUpgrade|upgradeToAndCall/ },
  { cls: "#4", label: "arithmetic: unchecked block", re: /\bunchecked\s*\{/ },
  { cls: "#5", label: "oracle read", re: /latestRoundData|getReserves\s*\(|\.slot0\s*\(/ },
  { cls: "#6", label: "ERC4626 vault conversion", re: /convertToShares|convertToAssets/ },
  { cls: "#7", label: "signatures: ecrecover", re: /\becrecover\b/ },
  { cls: "#12", label: "deploy: selfdestruct", re: /\bselfdestruct\b/ },
  { cls: "#3", label: "inline assembly", re: /\bassembly\s*\{/ },
  { cls: "#2", label: "initialize() entrypoint", re: /function\s+initialize\b/ },
];
const PER_CLASS_CAP = 12;

function scanSource(dir) {
  const files = findFiles(dir, (n) => n.endsWith(".sol"));
  const byClass = new Map();
  for (const f of files) {
    let lines; try { lines = readFileSync(f, "utf8").split("\n"); } catch { continue; }
    const rel = relative(dir, f);
    for (let i = 0; i < lines.length; i++) {
      for (const p of LEAD_PATTERNS) {
        if (p.re.test(lines[i])) {
          const key = p.cls + " " + p.label;
          if (!byClass.has(key)) byClass.set(key, { cls: p.cls, label: p.label, hits: [], total: 0 });
          const e = byClass.get(key); e.total++;
          if (e.hits.length < PER_CLASS_CAP) e.hits.push({ file: rel, line: i + 1, text: lines[i].trim().slice(0, 140) });
        }
      }
    }
  }
  return { byClass, totalFiles: files.length };
}

function checkHygiene(dir) {
  const out = { framework: null, solc: new Set(), oldPragma: false };
  if (findFiles(dir, (n) => n === "foundry.toml").length) out.framework = "Foundry";
  else if (findFiles(dir, (n) => /^hardhat\.config\.(js|ts|cjs)$/.test(n)).length) out.framework = "Hardhat";
  for (const f of findFiles(dir, (n) => n.endsWith(".sol"))) {
    let t; try { t = readFileSync(f, "utf8"); } catch { continue; }
    for (const m of t.matchAll(/pragma\s+solidity\s+([^;]+);/g)) {
      const v = m[1].trim(); out.solc.add(v);
      if (/0\.[0-7]\b|\^0\.[0-7]|<\s*0\.8/.test(v)) out.oldPragma = true;
    }
  }
  return { framework: out.framework, solc: [...out.solc].slice(0, 8), oldPragma: out.oldPragma };
}

function esc(s) { return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }

function renderReport(meta, deps, hygiene, source) {
  const md = [];
  md.push(`# Security scan — ${meta.owner}/${meta.repo}`, "");
  md.push(`**Repo:** https://github.com/${meta.owner}/${meta.repo} · **Scanned:** ${meta.date} · **Files:** ${source.totalFiles} Solidity files`, "");
  md.push("> A hygiene + known-class scan, not an audit. Dependency advisories are matched against your **exact pinned versions**. Code items are **leads to confirm by reading**, not confirmed vulnerabilities. This scan does not certify the absence of bugs.", "");
  md.push("## 1. Dependency advisories (your pinned versions)", "");
  if (!deps.advisories.length) md.push("No advisory affects the exact npm versions pinned in your lockfile. ✅");
  else for (const a of deps.advisories) md.push(`- **[${a.severity}]** [${a.id}](${a.url}) — ${a.summary}\n  affects: ${a.packages.join(", ")}`);
  md.push("");
  md.push("## 2. Build hygiene", "");
  md.push(`- Framework: **${hygiene.framework || "not detected"}**`);
  md.push(`- Solidity pragmas: **${hygiene.solc.length ? hygiene.solc.join(", ") : "not detected"}**${hygiene.oldPragma ? " — ⚠️ a pragma allows < 0.8 (no built-in overflow checks; class #4)" : ""}`);
  md.push("- solc known bugs: cross-check against https://docs.soliditylang.org/en/latest/bugs.html", "");
  md.push("## 3. Code leads by class", "");
  md.push("Grep-level leads mapped to the [14-class checklist](https://github.com/OxToF/evm-security-watch). Each is a place to look, confirmed by reading the surrounding code.", "");
  const classes = [...source.byClass.values()].sort((a, b) => b.total - a.total);
  if (!classes.length) md.push("No lead patterns matched.");
  else {
    md.push("| Class | Lead | Hits |", "|---|---|---|");
    for (const e of classes) md.push(`| ${e.cls} | ${e.label} | ${e.total} |`);
    md.push("");
    for (const e of classes) { md.push(`### ${e.cls} — ${e.label} (${e.total})`); for (const h of e.hits) md.push(`- \`${h.file}:${h.line}\` — \`${h.text}\``); if (e.total > e.hits.length) md.push(`- … and ${e.total - e.hits.length} more`); md.push(""); }
  }
  md.push("---", "", "_Generated by [evm-security-watch](https://github.com/OxToF/evm-security-watch). Want continuous coverage instead of a snapshot? A monthly watch diffs new advisories and newly-merged code._");
  return { md: md.join("\n"), html: renderHtml(meta, deps, hygiene, source, classes) };
}

function renderHtml(meta, deps, hygiene, source, classes) {
  const sev = (s) => /CRIT/i.test(s) ? "#b00020" : /HIGH/i.test(s) ? "#d1440a" : /MOD|MED/i.test(s) ? "#b8860b" : "#555";
  const depRows = deps.advisories.length ? deps.advisories.map((a) =>
    `<tr><td><span class="sev" style="background:${sev(a.severity)}">${esc(a.severity)}</span></td><td><a href="${esc(a.url)}">${esc(a.id)}</a><div class="muted">${esc(a.packages.join(", "))}</div></td><td>${esc(a.summary)}</td></tr>`).join("")
    : `<tr><td colspan="3" class="ok">No advisory affects your pinned versions.</td></tr>`;
  const classRows = classes.map((e) => `<tr><td>${esc(e.cls)}</td><td>${esc(e.label)}</td><td>${e.total}</td></tr>`).join("") || `<tr><td colspan="3">No lead patterns matched.</td></tr>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Scan — ${esc(meta.owner)}/${esc(meta.repo)}</title>
<style>:root{--fg:#1a1a2e;--muted:#6b7280;--card:#f7f7fb;--line:#e5e7eb}body{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;color:var(--fg);max-width:820px;margin:auto;padding:2rem}h1{font-size:1.5rem;margin:0 0 .2rem}h2{font-size:1.15rem;margin:2rem 0 .6rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}.note{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.8rem 1rem;margin:1rem 0;font-size:.92rem}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:.45rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}.sev{color:#fff;border-radius:5px;padding:.1rem .45rem;font-size:.72rem;font-weight:700}.muted{color:var(--muted);font-size:.82rem}.ok{color:#0a7d33}code{background:var(--card);padding:.05rem .3rem;border-radius:4px}</style></head><body>
<h1>Security scan — ${esc(meta.owner)}/${esc(meta.repo)}</h1>
<div class="muted">Scanned ${esc(meta.date)} · ${source.totalFiles} Solidity files</div>
<div class="note"><strong>A hygiene + known-class scan, not an audit.</strong> Advisories matched against your exact pinned versions. Code items are leads to confirm, not confirmed vulnerabilities.</div>
<h2>1. Dependency advisories (pinned versions)</h2><table><tr><th>Sev</th><th>ID</th><th>Summary</th></tr>${depRows}</table>
<h2>2. Build hygiene</h2><table><tr><td>Framework</td><td>${esc(hygiene.framework || "not detected")}</td></tr><tr><td>Solidity</td><td>${esc(hygiene.solc.join(", ") || "n/a")}${hygiene.oldPragma ? ' <b style="color:#d1440a">(allows &lt;0.8)</b>' : ""}</td></tr></table>
<h2>3. Code leads by class</h2><table><tr><th>Class</th><th>Lead</th><th>Hits</th></tr>${classRows}</table>
<footer style="margin-top:2rem;color:var(--muted);font-size:.85rem;border-top:1px solid var(--line);padding-top:1rem">Generated by <a href="https://github.com/OxToF/evm-security-watch">evm-security-watch</a>.</footer></body></html>`;
}

export async function runScan(opts = {}) {
  const { repoUrl, localPath = null, out = "scan-out", fetchImpl = globalThis.fetch, now = new Date(), log = console.log } = opts;
  let dir, owner, repo;
  if (localPath) { dir = localPath; owner = "local"; repo = localPath.split(sep).filter(Boolean).pop() || "repo"; }
  else { const g = parseGithubUrl(repoUrl); owner = g.owner; repo = g.repo; dir = mkdtempSync(join(tmpdir(), "evm-scan-")); cloneRepo(g.url, dir, log); }
  const deps = readDeps(dir);
  if (!deps.length) log("[scan] no package-lock.json / yarn.lock found — dependency section will be empty");
  const depResult = deps.length ? await scanDependencies(deps, fetchImpl, log) : { advisories: [], failures: 0 };
  const hygiene = checkHygiene(dir);
  const source = scanSource(dir);
  const date = now.toISOString().slice(0, 10);
  const meta = { owner, repo, date };
  const { md, html } = renderReport(meta, depResult, hygiene, source);
  mkdirSync(out, { recursive: true });
  const base = `${owner}-${repo}-${date}`.replace(/[^A-Za-z0-9_.-]/g, "_");
  const mdPath = join(out, `${base}.md`), htmlPath = join(out, `${base}.html`);
  writeFileSync(mdPath, md); writeFileSync(htmlPath, html);
  log(`[scan] ${depResult.advisories.length} dep advisories · ${[...source.byClass.values()].reduce((s, e) => s + e.total, 0)} code leads · ${source.totalFiles} files`);
  log(`[scan] report -> ${mdPath}`); log(`[scan] report -> ${htmlPath}`);
  return { meta, deps: depResult, hygiene, source, mdPath, htmlPath };
}
