---
description: One security-watch pass over an EVM / Solidity repo — deps + static analysis + risky-pattern grep + recent advisories → a dated report. Proposes fixes, never applies them.
argument-hint: "[path-to-solidity-repo]"
---

# /security-watch

Run one **watch pass** over the Solidity repo at `$ARGUMENTS` (default: current
directory). Produce a dated report. **Propose, don't apply** — never patch
production code.

## Step 1 — Dependency & compiler scan

1. Parse `package.json` / `foundry.toml` / `remappings.txt` / lockfiles.
2. For each security-relevant library (`@openzeppelin/contracts`, `solmate`,
   `solady`, oracle/bridge SDKs), look up the version against the
   [GitHub Advisory DB](https://github.com/advisories) — flag any version inside
   an advisory range.
3. Read the `solc` version (pragma + config) and check it against the
   [official Solidity known-bugs list](https://docs.soliditylang.org/en/latest/bugs.html).
4. Confirm `optimizer` settings and that the deployed contract (if any) is
   verified on the block explorer.

## Step 2 — Static analysis (when tooling is available)

Run what's installed and triage detectors by severity:

```bash
slither . --json -        # reference detector
aderyn .                  # fast Rust detector
# myth analyze <contract> # symbolic, for a specific contract
```

If no tool is installed, skip to Step 3 and note it in the report.

## Step 3 — Risky-pattern grep → triaged leads

Grep the source for leads, then **confirm each by reading the body** (a hit is a
lead, not a finding). Map each confirmed lead to a class in
[`skill/vuln-classes.md`](../skill/vuln-classes.md):

| Grep | Class to check |
|---|---|
| `delegatecall` | #3 proxy / arbitrary delegatecall |
| `initialize` without `initializer` / no `_disableInitializers()` | #3 / #12 uninitialized proxy |
| `tx.origin` | #2 access control |
| `unchecked` , `uint128(` , `uint64(` | #4 arithmetic |
| `.transfer(` / `.transferFrom(` / `.approve(` on IERC20 | #8 non-standard tokens |
| `ecrecover` , `permit` | #7 signatures |
| `latestRoundData` / `slot0` / `getReserves` | #5 oracle |
| external call before state write | #1 reentrancy |
| `withdraw` / privileged fund movement | #13 fund-flow / centralization |
| `for (` over user-growable arrays | #9 DoS |
| swap call without `minOut` | #10 MEV |

## Step 4 — Recent advisories (WebSearch, last 48h)

Sweep the sources in [`skill/daily-watch.md`](../skill/daily-watch.md) §1. For each
fresh technique, ask: *does this class exist in this repo?* If yes, add a finding.

## Step 5 — Emit the dated report

Append to the repo's `SECURITY_WATCH.md` (create it if absent):

```
### <YYYY-MM-DD> — Watch pass (<model>)

**Target:** <repo> @ <commit>
**Sources swept:** <list>

#### Dependency / compiler
| Check | Result |
|---|---|

#### Findings
| # | Class | Surface (file:line) | Severity | Proposed fix |
|---|---|---|---|---|

# or: RAS — nothing relevant. Sources swept: <list>.
```

Use the severity rubric in [`skill/daily-watch.md`](../skill/daily-watch.md).
**Never auto-apply a fix.**
