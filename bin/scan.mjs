// `scan` — the per-repo product. Point it at a public GitHub Solidity repo and it
// produces the dated report a customer receives: (1) dependency advisories on the
// repo's EXACT pinned npm versions (OSV/GitHub Advisory DB), (2) build hygiene
// (Solidity pragma range, framework), and (3) code leads mapped to the 14-class
// EVM checklist. Deterministic and near-zero cost: OSV + local grep, no compiler.

import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { normalize } from "./collect.mjs";
import { resolveSubmodules, parseSoldeerLock, readRemappings, productionImports, isTestOrScript, pragmaExcludes08, configuredSolc, TEST_ONLY_PACKAGES } from "./deps.mjs";

const OSV_QUERY = "https://api.osv.dev/v1/query";

export function parseGithubUrl(input) {
  const m = String(input).trim().match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/);
  if (!m) throw new Error(`not a public https://github.com/<owner>/<repo> URL: ${input}`);
  return { owner: m[1], repo: m[2], url: `https://github.com/${m[1]}/${m[2]}.git` };
}

// Tarball through the GitHub API rather than `git clone`: anonymous clones from a
// datacenter IP get throttled (intermittent 401 "could not read Username").
async function fetchRepo(owner, repo, workdir, log, fetchImpl, token) {
  log(`[scan] downloading ${owner}/${repo} tarball`);
  const headers = { "User-Agent": "evm-security-watch", Accept: "application/vnd.github+json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetchImpl(`https://api.github.com/repos/${owner}/${repo}/tarball`, { headers });
  if (!res.ok) throw new Error(`GitHub tarball ${res.status} for ${owner}/${repo}`);
  const tgz = join(workdir, "_repo.tar.gz");
  writeFileSync(tgz, Buffer.from(await res.arrayBuffer()));
  execFileSync("tar", ["-xzf", tgz, "-C", workdir], { stdio: ["ignore", "ignore", "pipe"], timeout: 120000 });
  const sub = readdirSync(workdir, { withFileTypes: true }).find((e) => e.isDirectory());
  if (!sub) throw new Error("empty tarball");
  return join(workdir, sub.name);
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

function readNpmDeps(dir) {
  const locks = findFiles(dir, (n) => n === "package-lock.json" || n === "yarn.lock");
  let pkgs = [];
  for (const lf of locks) {
    const t = readFileSync(lf, "utf8");
    pkgs = pkgs.concat((lf.endsWith("yarn.lock") ? parseYarnLock(t) : parsePackageLock(t)).map((d) => ({ ...d, source: "npm" })));
  }
  return { pkgs, lockfiles: locks.length };
}

// Split advisories by whether the affected package reaches deployed bytecode.
// On-chain: a production .sol file imports it. Everything else (Hardhat, ethers,
// babel, forge-std…) only runs on a developer's machine or in CI.
export function triageAdvisories(advisories, onchainNames) {
  const onchain = [], toolchain = [];
  for (const a of advisories) {
    const names = a.packages.map((p) => p.slice(0, p.lastIndexOf(" ")));
    (names.some((n) => onchainNames.has(n) && !TEST_ONLY_PACKAGES.has(n)) ? onchain : toolchain).push(a);
  }
  return { onchain, toolchain };
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
  const all = findFiles(dir, (n) => n.endsWith(".sol"));
  const files = all.filter((f) => !isTestOrScript(relative(dir, f)));
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
  return { byClass, totalFiles: files.length, excludedFiles: all.length - files.length };
}

// A pragma is only a problem when no 0.8 compiler can build the file (then it
// has no built-in overflow checks). ">=0.5.0" on an interface compiled with
// 0.8.19 is fine, and flagging it would be noise.
function checkHygiene(dir) {
  const out = { framework: null, solc: new Set(), oldFiles: [] };
  if (findFiles(dir, (n) => n === "foundry.toml").length) out.framework = "Foundry";
  else if (findFiles(dir, (n) => /^hardhat\.config\.(js|ts|cjs)$/.test(n)).length) out.framework = "Hardhat";
  const configured = configuredSolc(dir);
  const configuredOld = configured ? /^0\.[0-7]\./.test(configured) : false;
  for (const f of findFiles(dir, (n) => n.endsWith(".sol"))) {
    const rel = relative(dir, f);
    if (isTestOrScript(rel)) continue;
    let t; try { t = readFileSync(f, "utf8"); } catch { continue; }
    for (const m of t.matchAll(/pragma\s+solidity\s+([^;]+);/g)) {
      const v = m[1].trim(); out.solc.add(v);
      if (configuredOld || pragmaExcludes08(v)) out.oldFiles.push(rel);
    }
  }
  return { framework: out.framework, configured, solc: [...out.solc].slice(0, 8), oldPragma: out.oldFiles.length > 0, oldFiles: [...new Set(out.oldFiles)] };
}

function esc(s) { return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }

function renderReport(meta, deps, hygiene, source) {
  const md = [];
  md.push(`# Security scan — ${meta.owner}/${meta.repo}`, "");
  md.push(`**Repo:** https://github.com/${meta.owner}/${meta.repo} · **Scanned:** ${meta.date} · **Files:** ${source.totalFiles} Solidity files`, "");
  md.push("> A hygiene + known-class scan, not an audit. Dependency advisories are matched against your **exact pinned versions**. Code items are **leads to confirm by reading**, not confirmed vulnerabilities. This scan does not certify the absence of bugs.", "");
  const advLine = (a) => `- **[${a.severity}]** [${a.id}](${a.url}) — ${a.summary}\n  affects: ${a.packages.join(", ")}`;
  const cov = deps.coverage;
  md.push("## 1. Dependency advisories (your pinned versions)", "");
  md.push(`Checked: ${cov.checked} pinned package version(s) (${cov.sources.join(", ") || "no dependency manifest found"}).`, "");
  md.push("### 1a. On-chain surface (libraries your deployed contracts import)", "");
  if (cov.noExternalImports) md.push("Your production contracts import no external library, so there is no on-chain dependency surface to check.");
  else if (!cov.checked) md.push("⚠️ **Not checked.** No dependency version could be resolved, so this scan says nothing about your libraries.");
  else if (!deps.buckets.onchain.length) md.push(`No advisory affects the resolved versions of the libraries your production contracts import${cov.unresolved.length ? ` (${cov.unresolved.length} other dependenc${cov.unresolved.length === 1 ? "y is" : "ies are"} listed under "Not checked")` : ""}.`);
  else for (const a of deps.buckets.onchain) md.push(advLine(a));
  md.push("", "### 1b. Toolchain, tests and scripts (never deployed)", "");
  if (!deps.buckets.toolchain.length) md.push("None.");
  else for (const a of deps.buckets.toolchain) md.push(advLine(a));
  if (cov.unresolved.length) {
    md.push("", "### 1c. Not checked", "", "These dependencies could not be tied to a published package version, so no advisory was looked up for them. Review them by hand.", "");
    for (const u of cov.unresolved) md.push(`- \`${u.path}\` (${u.url})${u.sha ? ` @ \`${u.sha.slice(0, 10)}\`` : ""}${u.production ? "" : " (tests/scripts only)"}: ${u.reason}`);
  }
  md.push("");
  md.push("## 2. Build hygiene", "");
  md.push(`- Framework: **${hygiene.framework || "not detected"}**`);
  md.push(`- Compiler pinned in config: **${hygiene.configured || "not pinned"}**`);
  md.push(`- Solidity pragmas (production files): **${hygiene.solc.length ? hygiene.solc.join(", ") : "not detected"}**`);
  if (hygiene.oldPragma) md.push(`- ⚠️ Compiled below 0.8 (no built-in overflow checks; class #4): ${hygiene.oldFiles.slice(0, 6).map((f) => `\`${f}\``).join(", ")}${hygiene.oldFiles.length > 6 ? ` and ${hygiene.oldFiles.length - 6} more` : ""}`);
  md.push("- solc known bugs: cross-check against https://docs.soliditylang.org/en/latest/bugs.html", "");
  md.push("## 3. Code leads by class", "");
  md.push(`Grep-level leads mapped to the [14-class checklist](https://github.com/OxToF/evm-security-watch), in production code only (${source.excludedFiles} test/script/mock files skipped). Each is a place to look, confirmed by reading the surrounding code.`, "");
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

export const WATCHDOG_LOGO = `<svg width="46" height="46" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="EVM Watchdog"><defs><linearGradient id="wg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#9945FF"/><stop offset="1" stop-color="#14F195"/></linearGradient></defs><circle cx="32" cy="32" r="30" fill="url(#wg)"/><path d="M16 24 L21 7 L27 20 Z" fill="#efe7d6"/><path d="M48 24 L43 7 L37 20 Z" fill="#efe7d6"/><path d="M19.5 21 L21.6 12 L24.4 19 Z" fill="#b98cff"/><path d="M44.5 21 L42.4 12 L39.6 19 Z" fill="#b98cff"/><ellipse cx="32" cy="34" rx="15" ry="14" fill="#f4eddd"/><ellipse cx="32" cy="41" rx="8" ry="6.5" fill="#fffaf0"/><path d="M21.5 29 L28 30.5" stroke="#3a3550" stroke-width="1.6" stroke-linecap="round"/><path d="M42.5 29 L36 30.5" stroke="#3a3550" stroke-width="1.6" stroke-linecap="round"/><circle cx="26" cy="33" r="3" fill="#20202f"/><circle cx="38" cy="33" r="3" fill="#20202f"/><circle cx="27" cy="32.1" r=".9" fill="#fff"/><circle cx="39" cy="32.1" r=".9" fill="#fff"/><ellipse cx="32" cy="38.5" rx="2.7" ry="2" fill="#20202f"/><path d="M32 40.5 Q28 44 25 42" stroke="#20202f" stroke-width="1.4" fill="none" stroke-linecap="round"/><path d="M32 40.5 Q36 44 39 42" stroke="#20202f" stroke-width="1.4" fill="none" stroke-linecap="round"/><circle cx="45" cy="45" r="7.5" fill="rgba(255,255,255,.18)" stroke="#20202f" stroke-width="2.4"/><path d="M50.4 50.4 L57 57" stroke="#20202f" stroke-width="3.4" stroke-linecap="round"/></svg>`;

function sevBg(s) {
  const u = String(s).toUpperCase();
  if (u.startsWith("CRIT")) return "#dc2626";
  if (u.startsWith("HIGH")) return "#ea580c";
  if (u.startsWith("MOD") || u.startsWith("MED")) return "#d97706";
  if (u.startsWith("LOW")) return "#2563eb";
  return "#64748b";
}

function renderHtml(meta, deps, hygiene, source, classes) {
  const bk = deps.buckets, cov = deps.coverage;
  const nAdv = bk.onchain.length;
  const nLeads = classes.reduce((s, e) => s + e.total, 0);
  // Worst severity on the on-chain surface only: an advisory in Hardhat or
  // ethers never ships in bytecode and must not headline the report.
  const worst = bk.onchain.reduce((w, a) => {
    const rank = { CRITICAL: 4, HIGH: 3, MODERATE: 3, MEDIUM: 3, LOW: 2 };
    const r = rank[String(a.severity).toUpperCase().split(" ")[0]] || 1;
    return r > w.r ? { r, label: a.severity } : w;
  }, { r: 0, label: "—" });

  const card = (a) => `<div class="adv"><span class="chip" style="background:${sevBg(a.severity)}">${esc(a.severity)}</span><div class="adv-body"><a class="adv-id" href="${esc(a.url)}">${esc(a.id)}</a><div class="adv-sum">${esc(a.summary)}</div><div class="adv-pkg">Affects: ${esc(a.packages.join(", "))}</div></div></div>`;
  const depCards = cov.noExternalImports
    ? `<div class="clean">✓ &nbsp;Your production contracts import no external library, so there is no on-chain dependency surface to check.</div>`
    : !cov.checked
    ? `<div class="notchecked">⚠ &nbsp;<b>Not checked.</b> No dependency version could be resolved, so this scan says nothing about your libraries.</div>`
    : nAdv ? bk.onchain.map(card).join("")
    : `<div class="clean">✓ &nbsp;No advisory affects the resolved versions of the libraries your production contracts import.${cov.unresolved.length ? ` ${cov.unresolved.length} other dependenc${cov.unresolved.length === 1 ? "y was" : "ies were"} not checked (see below).` : ""}</div>`;
  const toolCards = bk.toolchain.length ? bk.toolchain.map(card).join("") : `<p class="muted">None.</p>`;
  const unresolvedList = cov.unresolved.length
    ? `<h2>Not checked</h2><p class="muted">These dependencies could not be tied to a published package version, so no advisory was looked up for them. Review them by hand.</p><ul class="samples">${cov.unresolved.map((u) => `<li><span class="loc">${esc(u.path)}</span><code>${esc(u.url)}${u.sha ? " @ " + esc(u.sha.slice(0, 10)) : ""}</code> <span class="muted">${esc(u.reason)}</span></li>`).join("")}</ul>`
    : "";

  const hygieneRows = `
    <div class="hyg"><span class="hyg-badge na">◆</span><div><b>Framework</b><div class="muted">${esc(hygiene.framework || "not detected")}</div></div></div>
    <div class="hyg"><span class="hyg-badge na">◆</span><div><b>Compiler pinned in config</b><div class="muted">${esc(hygiene.configured || "not pinned")}</div></div></div>
    <div class="hyg"><span class="hyg-badge ${hygiene.oldPragma ? "warn" : "good"}">${hygiene.oldPragma ? "⚠" : "✓"}</span><div><b>Solidity pragmas (production files)</b><div class="muted">${esc(hygiene.solc.join(", ") || "not detected")}${hygiene.oldPragma ? ` — compiled below 0.8, no built-in overflow checks (class #4): ${esc(hygiene.oldFiles.slice(0, 6).join(", "))}${hygiene.oldFiles.length > 6 ? ` and ${hygiene.oldFiles.length - 6} more` : ""}.` : ""}</div></div></div>`;

  const classSections = classes.length
    ? classes.map((e) => `<div class="cls"><div class="cls-head"><span class="cls-tag">${esc(e.cls)}</span><span class="cls-label">${esc(e.label)}</span><span class="cls-count">${e.total}</span></div><ul class="samples">${e.hits.map((h) => `<li><span class="loc">${esc(h.file)}:${h.line}</span><code>${esc(h.text)}</code></li>`).join("")}${e.total > e.hits.length ? `<li class="more">… and ${e.total - e.hits.length} more</li>` : ""}</ul></div>`).join("")
    : `<div class="clean">No lead patterns matched.</div>`;

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security scan — ${esc(meta.owner)}/${esc(meta.repo)}</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#eceef4;color:#1c2030;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.doc{max-width:840px;margin:28px auto;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 12px 40px rgba(20,20,50,.12)}
.hd{background:linear-gradient(125deg,#1a0f36 0%,#0e1730 60%,#0a1f2b 100%);color:#fff;padding:26px 34px;display:flex;align-items:center;gap:16px;position:relative}
.hd::after{content:"";position:absolute;left:0;right:0;bottom:0;height:3px;background:linear-gradient(90deg,#9945FF,#14F195)}
.hd .wm{font-weight:800;letter-spacing:.5px;font-size:1.15rem;line-height:1.1}
.hd .wm .g{background:linear-gradient(90deg,#b98cff,#14F195);-webkit-background-clip:text;background-clip:text;color:transparent}
.hd .tl{color:#a9b0cf;font-size:.82rem;margin-top:3px}
.hd .date{margin-left:auto;text-align:right;color:#a9b0cf;font-size:.8rem}
.hd .date b{color:#fff;display:block;font-size:.95rem}
.sub{padding:22px 34px 6px}
.repo{font-size:1.5rem;font-weight:800;margin:0;letter-spacing:-.01em;word-break:break-word}
.repo a{color:inherit;text-decoration:none}
.pills{margin:10px 0 4px;display:flex;gap:8px;flex-wrap:wrap}
.pill{font-size:.74rem;font-weight:700;padding:.22rem .6rem;border-radius:999px;background:#eef0f6;color:#5b6178}
.pill.warn{background:#fff2e8;color:#c2410c}
.body{padding:14px 34px 30px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:18px 0 8px}
.stat{background:#f7f8fc;border:1px solid #eaecf3;border-radius:14px;padding:16px 18px}
.stat .num{font-size:2rem;font-weight:800;line-height:1}
.stat .lab{color:#6b7188;font-size:.8rem;margin-top:6px}
.stat.alert .num{color:#dc2626}
h2{font-size:1.05rem;margin:30px 0 12px;padding-left:12px;border-left:4px solid #9945FF;line-height:1.2}
.adv{display:flex;gap:12px;align-items:flex-start;padding:13px 0;border-top:1px solid #eef0f5}.adv:first-of-type{border-top:0}
.chip{color:#fff;border-radius:6px;padding:.16rem .5rem;font-size:.68rem;font-weight:800;letter-spacing:.3px;white-space:nowrap;margin-top:2px;flex:none}
.adv-id{font-weight:700;color:#4f2bbd;text-decoration:none;font-size:.95rem}.adv-id:hover{text-decoration:underline}
.adv-sum{margin:2px 0 3px}.adv-pkg{color:#8189a3;font-size:.8rem}
.notchecked{background:#fff7e6;border:1px solid #f5d9a8;color:#9a5b00;border-radius:12px;padding:14px 16px}
.clean{background:#effaf3;border:1px solid #c9eed7;color:#0a7d43;border-radius:12px;padding:14px 16px;font-weight:600}
.hyg{display:flex;gap:12px;align-items:flex-start;padding:10px 0}
.hyg-badge{width:26px;height:26px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;flex:none;font-size:.85rem}
.hyg-badge.good{background:#e7f8ee;color:#0a7d43}.hyg-badge.warn{background:#fff2e8;color:#c2410c}.hyg-badge.na{background:#eef0f6;color:#6b7188}
.cls{border:1px solid #eef0f5;border-radius:12px;padding:12px 14px;margin:10px 0;background:#fbfbfe}
.cls-head{display:flex;align-items:center;gap:10px}
.cls-tag{font-weight:800;color:#4f2bbd;background:#efe8ff;border-radius:6px;padding:.1rem .45rem;font-size:.8rem}
.cls-label{font-weight:600}.cls-count{margin-left:auto;color:#6b7188;font-weight:700}
.samples{list-style:none;margin:10px 0 0;padding:0}
.samples li{padding:5px 0;border-top:1px dashed #eceef4;font-size:.82rem}
.samples .loc{color:#9245ff;font-weight:600;margin-right:8px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.samples code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#f4f4fb;padding:.05rem .3rem;border-radius:4px;color:#333}
.samples .more{color:#9aa0b4;font-style:italic;border-top:0}
.muted{color:#8189a3;font-size:.82rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.scope{background:#f7f8fc;border:1px solid #eaecf3;border-radius:12px;padding:14px 16px;margin:22px 0 4px;font-size:.9rem;color:#4a5069}
.ft{border-top:1px solid #eef0f5;margin-top:24px;padding-top:16px;display:flex;align-items:center;gap:10px;color:#8189a3;font-size:.82rem}
.ft b{color:#4a5069}
a{color:#6d3bd6}
@media print{body{background:#fff}.doc{box-shadow:none;margin:0;max-width:none}}
</style></head><body>
<div class="doc">
  <div class="hd">
    ${WATCHDOG_LOGO}
    <div><div class="wm">EVM <span class="g">WATCHDOG</span></div><div class="tl">EVM &amp; Solidity security scan</div></div>
    <div class="date">Report date<b>${esc(meta.date)}</b></div>
  </div>
  <div class="sub">
    <h1 class="repo"><a href="https://github.com/${esc(meta.owner)}/${esc(meta.repo)}">${esc(meta.owner)}/${esc(meta.repo)}</a></h1>
    <div class="pills"><span class="pill">${source.totalFiles} production Solidity files · ${source.excludedFiles} test/script skipped</span><span class="pill">${cov.checked} dependency versions checked</span><span class="pill warn">Hygiene scan · not an audit</span></div>
  </div>
  <div class="body">
    <div class="stats">
      <div class="stat ${nAdv ? "alert" : ""}"><div class="num">${cov.checked || cov.noExternalImports ? nAdv : "?"}</div><div class="lab">Advisories on your<br>on-chain surface</div></div>
      <div class="stat"><div class="num">${nLeads}</div><div class="lab">Code leads in production<br>code, ${classes.length} classes</div></div>
      <div class="stat"><div class="num">${worst.label === "—" ? "—" : esc(String(worst.label).split(" ")[0])}</div><div class="lab">Highest advisory<br>severity</div></div>
    </div>
    <h2>Dependency advisories: on-chain surface</h2>
    <p class="muted">Libraries your production contracts import, matched against the exact versions pinned (${esc(cov.sources.join(", ") || "no dependency manifest found")}).</p>
    ${depCards}
    <h2>Toolchain, tests and scripts</h2>
    <p class="muted">Advisories in packages that never reach deployed bytecode (build tools, test libraries, scripts).</p>
    ${toolCards}
    ${unresolvedList}
    <h2>Build hygiene</h2>
    ${hygieneRows}
    <h2>Code leads by class</h2>
    <p class="muted">Grep-level leads mapped to the 14-class EVM/Solidity checklist. Each is a place to look, confirmed by reading the surrounding code — not a confirmed vulnerability.</p>
    ${classSections}
    <div class="scope"><b>What this is not.</b> A full audit is not replaceable. This scan detects known vulnerability classes and dependency issues; it does not certify the absence of bugs. Use it as a first line of defense, not a guarantee.</div>
    <div class="ft"><span>${WATCHDOG_LOGO.replace('width="46" height="46"', 'width="22" height="22"')}</span><div>Generated by <b>EVM Watchdog</b> · <a href="https://github.com/OxToF/evm-security-watch">open source</a>. Want continuous coverage instead of a snapshot? Ask about the monthly watch.</div></div>
  </div>
</div>
</body></html>`;
}

export async function runScan(opts = {}) {
  const { repoUrl, localPath = null, out = "scan-out", fetchImpl = globalThis.fetch, now = new Date(), log = console.log, token = process.env.GITHUB_TOKEN || null } = opts;
  let dir, owner, repo, cleanup = null;
  if (localPath) { dir = localPath; owner = "local"; repo = localPath.split(sep).filter(Boolean).pop() || "repo"; }
  else {
    const g = parseGithubUrl(repoUrl); owner = g.owner; repo = g.repo;
    const work = mkdtempSync(join(tmpdir(), "evm-scan-"));
    dir = await fetchRepo(owner, repo, work, log, fetchImpl, token);
    cleanup = work;
  }

  // Three sources of pinned versions: npm lockfiles, Soldeer, git submodules.
  const npm = readNpmDeps(dir);
  const soldeerFile = join(dir, "soldeer.lock");
  const soldeer = existsSync(soldeerFile) ? parseSoldeerLock(readFileSync(soldeerFile, "utf8")) : [];
  const subs = await resolveSubmodules(dir, localPath ? null : { owner, repo }, { fetchImpl, token, log });
  const resolved = [...npm.pkgs, ...soldeer, ...subs.filter((d) => d.status === "resolved").map((d) => ({ name: d.name, version: d.version, source: "submodule" }))];
  const sources = [];
  if (npm.lockfiles) sources.push(`${npm.lockfiles} npm lockfile(s)`);
  if (soldeer.length) sources.push("soldeer.lock");
  if (subs.length) sources.push(`${subs.length} git submodule(s), version read from package.json at the pinned commit`);
  if (!resolved.length) log("[scan] no dependency version could be resolved — dependency section will say NOT CHECKED");
  const depResult = resolved.length ? await scanDependencies(resolved, fetchImpl, log) : { advisories: [], failures: 0 };

  // Which of those reach deployed bytecode: follow production imports.
  const solFiles = findFiles(dir, (n) => n.endsWith(".sol"));
  const used = productionImports(dir, solFiles, readRemappings(dir), subs.map((d) => d.path));
  const onchainNames = new Set();
  for (const d of subs) if (d.status === "resolved" && used.has(d.path)) onchainNames.add(d.name);
  for (const d of [...npm.pkgs, ...soldeer]) if (used.has(d.name) || (d.soldeerName && used.has(d.soldeerName))) onchainNames.add(d.name);
  depResult.buckets = triageAdvisories(depResult.advisories, onchainNames);
  depResult.coverage = {
    checked: new Set(resolved.map((d) => `${d.name}@${d.version}`)).size,
    sources,
    unresolved: subs.filter((d) => d.status !== "resolved").map((d) => ({ ...d, production: used.has(d.path) })),
    submodules: subs,
    // Nothing to check at all: production code imports no dependency.
    noExternalImports: !subs.some((d) => used.has(d.path)) && ![...npm.pkgs, ...soldeer].some((d) => used.has(d.name) || (d.soldeerName && used.has(d.soldeerName))),
  };
  const hygiene = checkHygiene(dir);
  const source = scanSource(dir);
  const date = now.toISOString().slice(0, 10);
  const meta = { owner, repo, date };
  const { md, html } = renderReport(meta, depResult, hygiene, source);
  mkdirSync(out, { recursive: true });
  const base = `${owner}-${repo}-${date}`.replace(/[^A-Za-z0-9_.-]/g, "_");
  const mdPath = join(out, `${base}.md`), htmlPath = join(out, `${base}.html`);
  writeFileSync(mdPath, md); writeFileSync(htmlPath, html);
  log(`[scan] ${depResult.buckets.onchain.length} on-chain advisories (of ${depResult.advisories.length}; ${depResult.coverage.checked} versions checked, ${depResult.coverage.unresolved.length} unresolved) · ${[...source.byClass.values()].reduce((s, e) => s + e.total, 0)} code leads · ${source.totalFiles} production files (${source.excludedFiles} test/script skipped)`);
  log(`[scan] report -> ${mdPath}`); log(`[scan] report -> ${htmlPath}`);
  return { meta, deps: depResult, hygiene, source, mdPath, htmlPath, cleanup };
}
