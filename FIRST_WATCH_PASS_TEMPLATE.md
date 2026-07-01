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
>
> **Rule (0), above both:** nothing goes in the "verified good" row unless it
> actually cleared [`daily-watch.md` §0](skill/daily-watch.md#0-verification-discipline--a-scientific-process-for-security-claims)
> — confidence tier tagged, control-surface checked, cross-verified if it's an
> on-chain read. A friendly-sounding row backed by a single untraced `eth_call`
> is the exact mistake this template exists to prevent. If the honest state is
> "closed-source, one open question, nothing verified above INFERRED" — write
> that instead of manufacturing a ✅ row.

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
> a first pass on audited/forked code is usually Low/Info, not Critical. Every
> row carries a **confidence tier** (`PROVEN` / `TESTED` / `VERIFIED-LIVE` /
> `VERIFIED-SOURCE` / `INFERRED` / `UNKNOWN` — daily-watch.md §0). A row you
> can't tag above `INFERRED` cannot be phrased as reassurance, and only a
> `PROVEN` row may use words like "cannot" or "impossible."

| # | Item | Severity | Confidence | Status |
|---|---|---|---|---|
| 1 | {{verified-good fact}} | ✅ Good | {{tier}} | Verified |
| 2 | {{design observation}} | {{Low/Med}} | {{tier}} | Design |
| 3 | {{design observation}} | {{Low}} | {{tier}} | Design |

**1 — {{title}} ({{tier}}).** {{What you checked on-chain / in source, INCLUDING
the negative check you ran (e.g. "checked `owner()` — held by a 3-of-5 Safe,
not an EOA; cross-verified the read against a second RPC") and why that's
reassuring. If the tier is `VERIFIED-LIVE`, say what a single-block on-chain
read does and does not prove.}}

**2 — {{title}} ({{severity}}, {{tier}}).** {{The observation, why it matters, and the proposed monitoring/fix. Propose, don't apply.}}

**3 — {{title}} ({{severity}}, {{tier}}).** {{…}}

## 3. Dependency / compiler

{{Stack + any advisory hit for pinned versions, or "none in this pass". Note the full
dependency cross-check is part of the recurring watch.}}

## 4. What a continuous watch adds

This free pass is a snapshot — anything tagged `VERIFIED-LIVE` above is true
*as of this block*, not guaranteed true tomorrow. The recurring watch:
- **re-verifies the closing-guard watchlist every pass** — every parameter that
  closes a known exploit for this lineage (§2 above) gets re-read, not just
  checked once at pitch time; a guard controlled by an EOA can be flipped
  silently between passes;
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
