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
