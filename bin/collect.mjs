// `collect` — pull current advisories (OSV, npm/GitHub-backed) for the EVM/Solidity
// dependency surface, diff against the last run, and write a dated report. The
// "watch" half of evm-security-watch. Zero runtime deps (Node >= 18 fetch).

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

// The npm packages an EVM/Solidity project actually pulls into its trust boundary.
export const DEFAULT_PACKAGES = [
  "@openzeppelin/contracts", "@openzeppelin/contracts-upgradeable",
  "@openzeppelin/upgrades-core", "solmate", "@solmate/utils",
  "@uniswap/v3-core", "@uniswap/v2-core", "@uniswap/v3-periphery",
  "@chainlink/contracts", "@aave/core-v3",
  "hardhat", "ethers", "web3", "@nomicfoundation/hardhat-toolbox",
  "solc", "@ensdomains/ens-contracts", "@account-abstraction/contracts",
];

const OSV_QUERY = "https://api.osv.dev/v1/query";

export async function queryPackage(name, fetchImpl, version) {
  const query = { package: { ecosystem: "npm", name } };
  if (version) query.version = version;
  const res = await fetchImpl(OSV_QUERY, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(query),
  });
  if (!res.ok) throw new Error(`OSV ${res.status} for ${name}`);
  return (await res.json()).vulns || [];
}

function canonicalId(ids) {
  return ids.find((i) => i.startsWith("GHSA-")) || ids.find((i) => i.startsWith("CVE-")) ||
    ids.find((i) => i.startsWith("RUSTSEC-")) || ids[0];
}
function severityOf(v) {
  if (v.database_specific && v.database_specific.severity) return String(v.database_specific.severity).toUpperCase();
  if (Array.isArray(v.severity) && v.severity.length) {
    const c = v.severity.find((s) => /CVSS/.test(s.type)); if (c) return c.score;
  }
  return "UNSPECIFIED";
}
const SEV_RANK = { CRITICAL: 0, HIGH: 1, MODERATE: 2, MEDIUM: 2, LOW: 3, UNSPECIFIED: 4 };
function sevRank(l) { const u = String(l).toUpperCase(); for (const k of Object.keys(SEV_RANK)) if (u.startsWith(k)) return SEV_RANK[k]; return 5; }

export function normalize(rawByPkg) {
  const byAlias = new Map();
  for (const [pkg, vulns] of rawByPkg) {
    for (const v of vulns) {
      if (v.withdrawn) continue;
      const ids = [v.id, ...(v.aliases || [])];
      let adv = null;
      for (const id of ids) if (byAlias.has(id)) { adv = byAlias.get(id); break; }
      if (!adv) adv = { ids: new Set(), pkgs: new Set(), summary: v.summary || v.details || "(no summary)", severity: severityOf(v), published: v.published || null };
      ids.forEach((id) => adv.ids.add(id));
      adv.pkgs.add(pkg);
      if (sevRank(severityOf(v)) < sevRank(adv.severity)) adv.severity = severityOf(v);
      if (v.published && (!adv.published || v.published < adv.published)) adv.published = v.published;
      ids.forEach((id) => byAlias.set(id, adv));
    }
  }
  const out = [], seen = new Set();
  for (const adv of byAlias.values()) {
    const cid = canonicalId([...adv.ids]); if (seen.has(cid)) continue; seen.add(cid);
    out.push({ id: cid, aliases: [...adv.ids].filter((i) => i !== cid).sort(), packages: [...adv.pkgs].sort(),
      severity: adv.severity, summary: adv.summary.replace(/\s+/g, " ").trim(), published: adv.published,
      url: cid.startsWith("GHSA-") ? `https://github.com/advisories/${cid}` : `https://osv.dev/vulnerability/${cid}` });
  }
  out.sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || a.id.localeCompare(b.id));
  return out;
}

function loadState(f) { if (!existsSync(f)) return { seenIds: [], runs: [] }; try { return JSON.parse(readFileSync(f, "utf8")); } catch { return { seenIds: [], runs: [] }; } }

function renderRow(a, isNew) {
  const pub = a.published ? a.published.slice(0, 10) : "—";
  const al = a.aliases.length ? ` (${a.aliases.join(", ")})` : "";
  return `- **[${a.severity}]** [${a.id}](${a.url})${isNew ? " 🆕" : ""} — ${a.summary}\n  packages: ${a.packages.join(", ")} · published ${pub}${al}`;
}

export async function runCollect(opts = {}) {
  const { out = "watch-reports", packages = DEFAULT_PACKAGES, fetchImpl = globalThis.fetch, now = new Date(), log = console.log } = opts;
  if (typeof fetchImpl !== "function") throw new Error("global fetch unavailable — needs Node >= 18");
  const raw = [], failures = [];
  for (const p of packages) { try { raw.push([p, await queryPackage(p, fetchImpl)]); } catch (e) { failures.push(`${p}: ${e.message}`); } }
  if (raw.length === 0) throw new Error(`all ${packages.length} advisory queries failed (offline?)`);
  const advisories = normalize(raw);
  const date = now.toISOString().slice(0, 10);
  const stateFile = join(out, "state.json");
  const state = loadState(stateFile); const seen = new Set(state.seenIds);
  const freshIds = advisories.filter((a) => !seen.has(a.id) && !a.aliases.some((x) => seen.has(x))).map((a) => a.id);
  mkdirSync(join(out, "reports"), { recursive: true });
  const fresh = new Set(freshIds);
  const md = [`# EVM security watch — ${date}`, "",
    `Advisories across the tracked EVM/Solidity dependency surface: **${advisories.length}** total, **${freshIds.length}** new since last run.`, "",
    "Source: OSV.dev (GitHub Advisory DB). Generated by `evm-security-watch collect`.", ""];
  if (freshIds.length) { md.push("## 🆕 New since last run", ""); for (const a of advisories.filter((a) => fresh.has(a.id))) md.push(renderRow(a, true)); md.push(""); }
  md.push("## All current advisories", ""); for (const a of advisories) md.push(renderRow(a, fresh.has(a.id))); md.push("");
  writeFileSync(join(out, "reports", `${date}.md`), md.join("\n"));
  writeFileSync(join(out, "reports", `${date}.json`), JSON.stringify({ date, total: advisories.length, new: freshIds, advisories }, null, 2) + "\n");
  const allIds = new Set(state.seenIds); for (const a of advisories) { allIds.add(a.id); a.aliases.forEach((x) => allIds.add(x)); }
  writeFileSync(stateFile, JSON.stringify({ seenIds: [...allIds].sort(), runs: [...(state.runs || []), { date, total: advisories.length, new: freshIds.length }].slice(-50) }, null, 2) + "\n");
  log(`[collect] ${advisories.length} advisories, ${freshIds.length} new -> ${join(out, "reports", date + ".md")}`);
  if (failures.length) log(`[collect] ${failures.length} package quer${failures.length === 1 ? "y" : "ies"} failed`);
  return { advisories, freshIds };
}
