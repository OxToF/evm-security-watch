---
description: One security-watch pass over an EVM / Solidity repo — deps + static analysis + risky-pattern grep + recent advisories → a dated report. Proposes fixes, never applies them.
argument-hint: "[path-to-solidity-repo]"
---

# /security-watch

Run one **watch pass** over the Solidity repo at `$ARGUMENTS` (default: current
directory). Produce a dated report. **Propose, don't apply** — never patch
production code.

**Verification discipline applies to every step below** — see
[`skill/daily-watch.md` §0](../skill/daily-watch.md#0-verification-discipline--a-scientific-process-for-security-claims).
No conclusion, positive or negative, ships without a confidence tier
(`PROVEN` / `TESTED` / `VERIFIED-LIVE` / `VERIFIED-SOURCE` / `INFERRED` /
`UNKNOWN`). A tool exiting clean, or an `eth_call` returning the expected
value, is a lead — it becomes a finding (including a "no finding") only once
the method, evidence, and refutation attempt behind it are written out.

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

## Step 2.5 — Formal verification attempt (`PROVEN` tier, where tractable)

For claims about arithmetic bounds, access-control reachability, or an
accounting invariant (classes #2, #4, #6, #13 in `vuln-classes.md`), attempt a
formal-verification tool **before** writing the claim as closed:

```bash
halmos --function invariant_ --loop 4                # symbolic testing, Z3-backed
hevm symbolic --code <bytecode> --sig "f(uint256)"    # symbolic execution
# certoraRun <spec>.spec                              # if a Certora key is available
```

- If the tool proves the property within stated bounds → `PROVEN`, and record
  the bounds (integer ranges, loop-unrolling depth, spec assumptions).
- If formal tooling isn't installed/feasible in the time budget → fall back to
  `forge test --match-test invariant` / Echidna (`TESTED`, record run count),
  and say explicitly that `PROVEN` wasn't attempted — don't let the report's
  wording imply more rigor than what ran.
- Classes that are inherently empirical (supply chain, MEV, off-chain/
  custodial) are never `PROVEN` — cap them at `VERIFIED-LIVE`/`VERIFIED-SOURCE`.

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

## Step 3.5 — Control-surface check (before calling anything "safe")

For every guard/parameter you're about to cite as mitigating a risk (a
`nonReentrant` modifier, a validator address, a pause flag, an `onlyOwner`
check), don't stop at "it's present." Resolve, and record in the report:

1. **Who can change it** — read `owner()` / `admin()` / the relevant role
   holder. Bare EOA, multisig, or timelock are three different risk pictures,
   not one.
2. **On-chain reads get cross-verified** — confirm any `eth_call` result
   against a second RPC endpoint before it backs a claim in the report.
   `scripts/call.js` supports `EVM_RPC=` overrides for this.
3. **Tag the resulting claim's confidence tier** per §0 — a guard confirmed
   present via one untraced `eth_call` is `VERIFIED-LIVE` at best (never
   `PROVEN` — that tier requires the formal-verification step above), and
   never phrased as a closed risk.

Skipping this step is how "the guard is active" quietly becomes "there's no
hole" — a false negative that reads like a clean audit.

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
| # | Class | Surface (file:line) | Severity | Confidence (method) | Evidence | Proposed fix |
|---|---|---|---|---|---|---|

# RAS is only valid if every applicable item reached PROVEN/TESTED/VERIFIED-LIVE.
# Otherwise: "No finding above <confidence> — <what's unverified>. Sources swept: <list>."
```

Use the severity rubric and confidence tiers in
[`skill/daily-watch.md`](../skill/daily-watch.md) (§0 for tiers, main body for
severity). **Never auto-apply a fix.**
