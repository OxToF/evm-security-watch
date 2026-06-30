# EVM Security Watch — a Claude Code skill

> Continuous security monitoring for EVM / Solidity smart contracts. Not a
> one-shot audit — a daily **watch** loop that pulls fresh ecosystem disclosures
> and re-confronts your contracts against each new exploit technique.

Audits are point-in-time; exploit techniques surface weekly. This skill turns
security into a repeatable loop:

> **Collect** fresh disclosures (exploits, post-mortems, CVEs, OpenZeppelin /
> Solidity advisories, L2 incidents) → **Confront** them against your contracts'
> code → **Report** a dated finding with severity, `file:line`, and a *proposed*
> fix. Propose only — never auto-patch production code.

It ships an executable `/security-watch` command that scans a target Solidity repo
for known vulnerability classes (reentrancy, access control, proxy/upgrade,
arithmetic, oracle manipulation, signature replay, fund-flow centralization,
supply-chain risk) and emits a dated report.

This is the EVM counterpart of
[`solana-security-watch`](https://github.com/OxToF/solana-security-watch) — same
loop, same discipline. Bug *classes* transpose across VMs: a fresh Solana exploit
can sharpen your EVM checklist, and vice-versa.

## What's inside

```
evm-security-watch/
├── SKILL.md                    # entry hub (progressive disclosure)
├── skill/
│   ├── daily-watch.md          # the collect → confront → report procedure + source list + severity rubric
│   └── vuln-classes.md         # 14 EVM/Solidity bug classes with detection leads + safe patterns
├── commands/
│   └── security-watch.md       # executable slash command: deps + static analysis + grep + advisories → report
├── scripts/
│   ├── call.js                 # on-chain recon CLI (selectors, eth_call, bytecode size/hash, storage)
│   └── package.json
├── LICENSE
└── README.md
```

## Install

**As a Claude Code skill** — drop this folder into your skills directory (e.g.
`~/.claude/skills/evm-security-watch/`).

**As a slash command** — copy `commands/security-watch.md` to
`~/.claude/commands/security-watch.md` (user-level) or
`.claude/commands/security-watch.md` (project-level).

## Use

```
/security-watch .                 # one watch pass over the current repo
/loop 1d /security-watch .        # self-paced daily watch
```

Or point a scheduled agent / cron job at the command with the repo path as
argument, appending each run to the repo's `SECURITY_WATCH.md` journal.

### On-chain recon helper

```bash
cd scripts && npm install
node call.js code   0x<addr>                 # deployed bytecode size
node call.js codehash 0x<addr>               # runtime-bytecode keccak (diff vs a known-good build)
node call.js call   0x<addr> "owner()"       # eth_call a getter
EVM_RPC=https://mainnet.base.org node call.js storage 0x<addr> 0x0   # read a storage slot
```

Defaults to Base Sepolia; override the endpoint with `EVM_RPC`.

## Demo — a real watch pass (Ramses V3, a $1B-class CL DEX)

To show the loop works on **real, complex, professionally-audited** code — not just
toy examples — here is a triage pass over
[`RamsesExchange/ramses-v3-contracts`](https://github.com/RamsesExchange/ramses-v3-contracts)
(168 contracts / ~22k LOC; a Uniswap-V3-style concentrated-liquidity ve(3,3) DEX,
audited by Consensys Diligence **and** Code4rena).

The watch's **collect → confront** step pulled Ramses's disclosure history, including
the [October 2024 reward-distribution exploit (~$90k)](https://www.quillaudits.com/blog/hack-analysis/ramses-exchange-exploit),
then re-confronted the current code against it. Honest result — **a single triage
pass found no new Critical/High** (as expected on twice-audited code), but it:

- **Re-located the exact exploit surface.** The 2024 hack abused reward claiming
  across `tokenId`s in the CL gauge. The pass walked straight to
  `GaugeV3._getReward` and confirmed the post-exploit fix is present.
- **Surfaced a real design observation the fix introduced:** that anti-sybil
  protection is **config-gated** — `if (address(rewardValidator) != address(0))` —
  and it leans on `tx.origin` as the sybil signal (fragile for smart-contract
  wallets / account-abstraction). It's a bolt-on mitigation living *outside* the
  reward-conservation invariant, not inside it.
- **Triaged 22k LOC** for risky patterns (`delegatecall`, `assembly`, `unchecked`,
  `tx.origin`) and cleared the benign ones by reading the source — *a hit is a
  lead, not a finding.*

The point isn't "we out-audited Consensys in one pass" — it's that the watch
**mechanically navigates to the highest-risk surface, grounded in that protocol's
own exploit history**, in minutes. That is what makes it valuable *between* audits,
run continuously.

## Try it on an intentionally-vulnerable repo

To validate detection without touching production code, point the command at a
public teaching corpus of known-vulnerable contracts — e.g.
[`crytic/not-so-smart-contracts`](https://github.com/crytic/not-so-smart-contracts)
or [`OpenZeppelin/damn-vulnerable-defi`](https://github.com/theredguild/damn-vulnerable-defi).
Their bugs are public and by-design, so a watch pass exercises the checklist
without accusing any live protocol:

```
git clone --depth 1 https://github.com/crytic/not-so-smart-contracts
/security-watch not-so-smart-contracts
```

## Design principles

- **Continuous, not point-in-time** — complements one-shot audit skills; keeps you
  current as new techniques drop.
- **Bug *classes*, not signatures** — a Solana exploit this week becomes an EVM
  checklist item, because the class (reentrancy, rounding, oracle, capture)
  transposes.
- **A hit is a lead, not a finding** — every grep/static candidate is confirmed by
  reading the source before it's reported.
- **Propose, don't apply** — on production code, flag and propose; a human gates
  every change.

## License

MIT — see `LICENSE`. Author: OxToF.
