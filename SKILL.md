---
name: evm-security-watch
description: >-
  Continuous security monitoring for EVM / Solidity smart contracts. Not a
  one-shot audit — a daily "watch" loop that pulls fresh ecosystem disclosures
  (exploits, post-mortems, CVEs, OpenZeppelin/Solidity advisories, L2 incidents)
  and re-confronts your contracts against each new technique. Ships an executable
  /security-watch command that scans a target Solidity repo for known
  vulnerability classes and emits a dated report.
license: MIT
author: OxToF
---

# EVM Security Watch

A skill for Claude Code that turns security from a **point-in-time audit** into a
**continuous watch**. Audits go stale the day after they ship — new exploit
techniques surface weekly across the EVM and L2 worlds, and most of them transpose
to bug *classes* (reentrancy, rounding, oracle manipulation, proxy/upgrade,
signature replay, access control) that may already exist in code that "passed
audit" months ago.

This skill encodes a repeatable daily loop:

> **Collect** fresh disclosures → **Confront** them against the target contracts'
> code → **Report** a dated entry with severity, `file:line`, and a proposed fix
> (propose only — never auto-patch production code).

> This is the EVM counterpart of
> [`solana-security-watch`](https://github.com/OxToF/solana-security-watch). Same
> loop, same discipline — bug *classes* transpose across VMs, so a fresh Solana
> account-substitution exploit can still sharpen your EVM access-control checklist,
> and vice-versa.

## When to use this skill

- You maintain a Solidity protocol and want a recurring security review.
- You want to react to a fresh exploit ("does this week's proxy-init takeover
  affect us?") by mechanically checking your own surfaces.
- You want a scheduled agent (cron / Claude Code `/loop`) to run the watch daily.
- You're reviewing a Solidity codebase and want a fast first-pass risk scan.

This skill complements one-shot audit skills (e.g. Trail of Bits-style review):
use those for depth on a frozen snapshot, use this to stay current over time.

## How it's organised (progressive disclosure)

Load only the file you need for the task at hand:

| File | Load it when… |
|---|---|
| [`skill/daily-watch.md`](skill/daily-watch.md) | Running the watch loop — the collect/confront/report procedure and source list. |
| [`skill/vuln-classes.md`](skill/vuln-classes.md) | Confronting code against bug classes — the EVM/Solidity checklist with detection patterns and safe patterns. |
| [`commands/security-watch.md`](commands/security-watch.md) | You want the mechanical scan: deps + static analysis + grep + advisory search → report. |
| [`scripts/call.js`](scripts/call.js) | You need on-chain recon against a deployed contract (selectors, `eth_call`, bytecode size/hash, storage slots). |

## The executable command

Install `commands/security-watch.md` as a Claude Code slash command and run
`/security-watch [path-to-solidity-repo]`. It will:

1. **Scan dependencies** — parse `package.json` / `foundry.toml` / remappings,
   cross-check `@openzeppelin/contracts` and other libs against GitHub Advisory DB,
   flag the `solc` version against the official known-bugs list.
2. **Run static analysis** — `slither` / `aderyn` over the repo when available,
   triaging detectors by severity.
3. **Grep risky patterns** — `delegatecall`, unprotected `initialize` / missing
   `_disableInitializers`, `tx.origin`, `unchecked` blocks, raw `transfer`/`call`
   without return checks, missing `nonReentrant`, unbounded loops.
4. **Pull recent advisories** — WebSearch the last 48h of EVM/Solidity/DeFi/L2
   disclosures.
5. **Emit a dated report** — `RAS` (nothing relevant) or per-finding: technique,
   surface, `file:line`, estimated severity, proposed fix. Never auto-applies.

## Core principle

**Propose, don't apply.** On production code, this skill flags and proposes — it
does not push fixes. Human validation gates every change. A grep hit is a *lead*,
not a finding: every candidate must be confirmed by reading the source.
