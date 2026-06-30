# First Watch Pass — report template

> The deliverable an [EVM Security Watch](README.md) engagement opens with: a short,
> honest **triage** anchored on the target's code lineage and exploit history — **not
> an audit**. Use it as a complimentary first pass, then as the recurring report
> format (append each pass to the target's `SECURITY_WATCH.md`).
>
> Replace every `{{PLACEHOLDER}}`. Keep it short. Two rules that make it convert
> instead of alarm: **(1)** lead with what's *verified good* — you are not a
> fear-seller; **(2)** end on an open question or a monitoring slot — that is the
> natural opening for a continuous watch.

---

# {{PROTOCOL}} — Complimentary First Watch Pass

**Prepared by:** {{HANDLE}} · EVM Security Watch (https://github.com/OxToF/evm-security-watch)
**Date:** {{YYYY-MM-DD}} · **Target chain:** {{CHAIN}}
**Method:** {{source review of `org/repo` | live on-chain bytecode recon (no public source)}}
**Nature:** a *watch pass* — a triage anchored on this code's lineage and exploit history. **This is not an audit.**

## TL;DR

{{2–3 sentences. State the lineage, the relevant prior exploit class, the single
most important verified fact (good or bad), and the gap a continuous watch closes.}}

## 1. What I looked at

- **Source / target:** {{repo + file count, or "closed-source → on-chain recon"}}
- **Lineage:** {{which audited/known protocol this forks, and the evidence —
  matching contract names, LOC deltas, identical accounting, etc.}}
- **Live state:** {{key deployed addresses — Voter / gauge / admin / factory}}

## 2. Findings & observations

> Order: put the ✅ *verified-good* row first; it disarms. Calibrate honestly —
> a first pass on audited/forked code is usually Low/Info, not Critical.

| # | Item | Severity | Status |
|---|---|---|---|
| 1 | {{verified-good fact}} | ✅ Good | Verified |
| 2 | {{design observation}} | {{Low/Med}} | Design |
| 3 | {{design observation}} | {{Low}} | Design |

**1 — {{title}} (Verified).** {{What you checked on-chain / in source and why it's reassuring.}}

**2 — {{title}} ({{severity}}).** {{The observation, why it matters, and the proposed monitoring/fix. Propose, don't apply.}}

**3 — {{title}} ({{severity}}).** {{…}}

## 3. Dependency / compiler

{{Stack + any advisory hit for pinned versions, or "none in this pass". Note the full
dependency cross-check is part of the recurring watch.}}

## 4. What a continuous watch adds

This free pass is a snapshot. The recurring watch:
- **alerts** if {{critical on-chain parameter / admin / guard}} ever changes;
- **diffs you against {{upstream}}** — every change you make from that codebase is
  uncovered by its audits, and that's where fork-specific bugs live;
- **confronts your contracts** against newly-disclosed exploits as they drop.

## 5. Open question

{{One specific thing you could NOT determine from source/on-chain — e.g. "who holds
proposer rights on your timelock?". This invites a reply and starts the conversation.}}

## 6. Scope & disclaimer

A best-effort triage, not a comprehensive audit; no guarantee of completeness.
Provided free of charge, no liability assumed. Findings are shared privately with
your team before any public disclosure.

---

### Reuse notes

- **Forked-and-exploited target** (you have the source): lead §2 with the *verified*
  state of the known-exploit fix, then the residual design weaknesses it left.
- **Closed-source target** (no repo): §1 method = "on-chain bytecode recon"; derive
  findings from proxy/immutability, admin type (EOA vs timelock vs Safe), and the
  gauge/reward lineage's exploit history. The §5 open question is your strongest line.
- Keep the whole thing to one screen. The recurring engagement is where depth lives.
