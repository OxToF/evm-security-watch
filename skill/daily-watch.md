# Daily watch — collect → confront → report

> The procedure for one watch pass over an EVM / Solidity codebase. Run it daily
> (or on every code change / deployment). Append each pass to the target repo's
> `SECURITY_WATCH.md` journal.

## Honest framing

There is no "official feed of LLM-detected vulnerabilities." This watch works by:
each day an agent **searches** recent disclosures (audits, post-mortems,
advisories, CVEs, researcher threads), then **re-audits** the target code in light
of those new techniques. Quality scales with the model — use the strongest
available for the finest detection.

This watch **does not replace a point-in-time audit**: it complements one by
tracking drift (new exploits, upgrades, admin changes) over time.

---

## 0. Verification discipline — a scientific process for security claims

The failure mode this section exists to kill: writing a reassuring conclusion
because it reads well, not because it was actually checked. A "no hole found"
that turns out to mean "I read one getter once" is worse than no report — it's
a false negative wearing the credibility of a security pass.

**The standard: every claim is a falsifiable hypothesis, tested by a stated
method, backed by reproducible evidence, and reported at the tier its method
actually earned — never higher.** This is also an honest boundary, not just a
tone: "mathematically proven" is a real, narrow category (formal verification
of code logic under stated bounds), not a rhetorical upgrade. Claims about
off-chain infra, key custody, or the absence of a future exploit **cannot** be
proven mathematically — they can only be tested empirically and labeled as
such. Dressing an empirical check up as a proof is exactly the complacency
this process exists to ban.

### Every claim: hypothesis → method → evidence → refutation attempt → residual uncertainty

1. **Hypothesis** — a specific, falsifiable statement. Not "reentrancy is
   handled" but "no external call in `Vault.sol` can re-enter a function that
   reads or writes `shares[msg.sender]` before that state is finalized."
2. **Method** — the exact tool + configuration used to test it (see
   Toolchain below). Precise enough that a third party can rerun it and get
   the same result — that's what turns it into evidence instead of an opinion.
3. **Evidence** — the actual artifact: proof transcript, invariant run count
   and seed, tx hash + block number, storage-slot value, source `file:line`.
   No artifact, no claim.
4. **Refutation attempt** — what you actively tried to break the hypothesis
   with, and it survived. A hypothesis nobody tried to falsify isn't verified
   — it's unchallenged. (E.g.: tried donation-attack sequencing on `deposit()`
   before `totalSupply() == 0`; tried flipping the guard via every function
   that writes to its storage slot.)
5. **Residual uncertainty** — what the method's scope does *not* cover.
   Formal proofs are bounded (integer widths, loop unrolling, spec
   assumptions); fuzzing is probabilistic; on-chain reads are point-in-time.
   State the boundary explicitly instead of letting the reader assume totality.

### Confidence tiers — tied to method, not to how confident the prose sounds

| Tier | Method | Claim license |
|---|---|---|
| **PROVEN** | Formal verification — SMT-based symbolic execution (Halmos, `hevm symbolic`) or a Certora Prover CVL spec — proves a property holds for *all* inputs within stated bounds. | The only tier allowed words like "cannot," "impossible," "guaranteed." Must state the bounds (integer ranges, loop-unrolling depth, spec assumptions). |
| **TESTED** | Property-based / invariant fuzzing (`forge test --match-test invariant`, Echidna) — N runs, given depth/seed, zero counterexamples. | "No counterexample found in `<N>` runs" — never "safe." Probabilistic, not proof; report the run count and config so it's reproducible. |
| **VERIFIED-LIVE** | On-chain read, cross-verified against a 2nd RPC, control-surface resolved (owner/admin/role holder identified). | Point-in-time fact only — "as of block `<N>`." Must be re-checked every pass. |
| **VERIFIED-SOURCE** | Manually traced logic in source, no tool. | Weakest "checked" tier — not mechanically reproducible by a third party. State what was traced and what wasn't. |
| **INFERRED** | Lineage/naming/pattern similarity, not diffed against its claimed origin. | A lead, never a conclusion. Cannot appear in a "verified good" row. |
| **UNKNOWN** | Could not be determined (closed-source, no RPC access, out of budget). | Must be listed explicitly — never smoothed into "looks fine." |

`RAS` is only valid when every applicable checklist item reached `PROVEN`,
`TESTED`, or `VERIFIED-LIVE`. Otherwise report what's actually known: "no
finding above INFERRED confidence — X and Y remain unverified."

### Non-negotiables

- **A single point-in-time read never proves safety.** Before writing anything
  stronger than `VERIFIED-LIVE`, resolve: (1) who controls the parameter —
  EOA vs. multisig vs. timelock change what "active" means entirely; (2) has
  it ever moved — check event/tx history, not just the current value; (3)
  cross-verify the read against a second independent RPC endpoint.
- **Lineage claims need a diff, not a name match.** "Forks Ramses" from
  matching contract/event names is `INFERRED` until the actual guarded
  function is diffed (bytecode or source) against the claimed upstream —
  matching names is exactly what a fork that changed the one line that
  matters would still have.
- **Every claim above `INFERRED` documents its refutation attempt**, not just
  the positive fact. "Reentrancy guard present" is an assertion; "ran Echidna
  20k calls / depth 50 targeting `Vault.withdraw` + `Vault.deposit`
  interleavings, zero counterexamples" is evidence. If you can't write the
  refutation attempt, you haven't done it — downgrade the tier instead of the
  wording.
- **Don't write a finding to make the report look better.** No padding
  Info/Low items to seem thorough, no soft-pedaling a Medium into an Info to
  keep a pitch friendly, no "everything looks solid" closer unless every
  relevant item cleared `PROVEN`/`TESTED`/`VERIFIED-LIVE`. If the honest state
  is "closed-source, one `UNKNOWN`, nothing above `VERIFIED-LIVE`" — that IS
  the report.

---

## 1. Collect — items from the last 24–48h

**Recent DeFi exploits / post-mortems** (all chains — bug classes transpose:
reentrancy, oracle, rounding, access control, proxy):

- [rekt.news](https://rekt.news/) — leaderboard + post-mortems
- BlockSec / Phalcon, PeckShield, SlowMist, CertiK alerts (X / blogs)
- [Immunefi](https://immunefi.com/explore/) — bug-bounty disclosures
- Code4rena / Cantina / Sherlock / Spearbit — recent contest findings

**EVM / Solidity / tooling advisories:**

- [OpenZeppelin security advisories](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories)
  + [GitHub Advisory DB (`@openzeppelin/contracts`)](https://github.com/advisories?query=openzeppelin)
- [Solidity compiler bugs](https://docs.soliditylang.org/en/latest/bugs.html) — the official list of known bugs per version
- Solidity releases (codegen changes that can introduce regressions)
- Trail of Bits / OpenZeppelin / ConsenSys Diligence / Dedaub blogs

**L2 / rollup specifics** (adapt to the target chain):

- Sequencer status pages + the chain's security docs — sequencer incidents, network upgrades
- [Optimism / OP-Stack security advisories](https://github.com/ethereum-optimism/optimism/security/advisories) (and the equivalent for Arbitrum / zk-stacks)
- Sequencer downtime → impact on time-dependent oracles / finality assumptions

**WebSearch keywords:** `"<chain> exploit"`, `"Solidity vulnerability"`,
`"reentrancy exploit"`, `"proxy upgrade exploit"`, `"uninitialized proxy"`,
`"access control exploit"`, `"oracle manipulation"`, `"ERC4626 inflation attack"`,
`"permit signature replay"`, `"stablecoin depeg exploit"`, `"delegatecall exploit"`,
`"L2 sequencer downtime"`.

---

## 2. Confront — for each technique found, check the target's exposure

> Requires the source repo available. Priority surfaces:

- **Access control** — does every mutative `external`/`public` function carry the
  right modifier (`onlyOwner`, `onlyRole`, `whenNotPaused`)? Is proxy `initialize`
  protected?
- **Reentrancy** — checks-effects-interactions respected? `nonReentrant` on
  functions making external calls / transfers? Read-only reentrancy?
- **Proxy / upgrade** — `_authorizeUpgrade` protected (UUPS)? Implementation
  initialized (`_disableInitializers` in the constructor)? No storage-layout
  collision across upgrades?
- **Fund flows** — who can withdraw? Internal accounting vs. real contract balance?
  Double-spend / payment replay?
- **Oracle / price** — manipulable price source (spot vs. TWAP)? Sanity checks?
  Staleness / sequencer-uptime feed on L2?
- **Tokens** — fee-on-transfer / rebasing / non-standard return handled
  (`SafeERC20`)? ERC777/ERC1155 hooks (reentrancy)?
- **Signatures** — EIP-712 domain correct? Anti-replay nonce? `ecrecover`
  malleability / `v,r,s` checks? `deadline` / expiry?
- **Pause / emergency** — entries covered; do user exits stay open?

> A grep/static hit is a **lead, not a finding**. Confirm each by reading the
> source before reporting. See [`vuln-classes.md`](vuln-classes.md) for the full
> checklist with detection and safe patterns.

---

## 3. Report — add a dated entry to the journal

- `RAS` (nothing relevant) — only when every applicable checklist item reached
  `PROVEN`, `TESTED`, or `VERIFIED-LIVE` (§0). Otherwise, say what's actually
  unverified instead of defaulting to `RAS`.
- Otherwise, per finding: technique, affected surface, `file:line`, estimated
  severity, **confidence tier + method + evidence** (§0), and a **proposed** fix.

> **Never auto-apply a fix to production code without human validation — propose,
> don't apply.**

### Severity rubric

| Severity | Meaning |
|---|---|
| **Critical** | Direct, unconditional loss of funds or full takeover; exploitable now. |
| **High** | Loss of funds / takeover under a realistic precondition; or unverifiable opaque control of funds. |
| **Medium** | Conditional or bounded impact; centralization risk that needs hardening before mainnet. |
| **Low** | Best-practice deviation, latent risk, or stale dependency with no current exploit path. |
| **Info** | Hygiene; no security impact on its own. |

---

## Toolchain

```bash
# Static analysis (leads only — every hit still needs source confirmation)
slither .                          # reference detector (Crytic / Trail of Bits)
aderyn .                           # Rust detector (Cyfrin), fast
myth analyze <contract>            # Mythril — symbolic execution
semgrep --config p/smart-contracts # Semgrep rules

# --- PROVEN tier: formal verification (SMT-backed, all-inputs-in-bounds) ---
halmos --function invariant_ --loop 4     # Halmos — symbolic testing on Foundry
                                           # test harness, Z3-backed
hevm symbolic --code <bytecode> --sig "f(uint256)"  # hevm symbolic execution /
                                           # equivalence checking, Z3/CVC5 backend
# Certora Prover — write a .spec (CVL), run via `certoraRun`; industry-standard
# for invariant proofs (requires a Certora key — note if unavailable and the
# claim stays capped at TESTED instead of PROVEN).

# --- TESTED tier: property-based / invariant fuzzing (probabilistic, not proof) ---
forge test                         # unit tests
forge test --match-test invariant  # invariant testing — record run count + seed
echidna <contract> --config echidna.yaml   # record test limit + corpus / seed

# --- VERIFIED-LIVE tier: on-chain (deployed contract) ---
# scripts/call.js: selectors, eth_call, bytecode size/hash, storage slots
# Cross-verify every read against a 2nd RPC (EVM_RPC= override) before it
# backs a claim — see §0.
# Block explorer API: watch events, admin txns, proxy upgrades (control-surface
# + "has it ever moved" checks)
# Tenderly: simulate / replay suspicious transactions
```

**Tractability note:** not every vuln class in `vuln-classes.md` is reachable
at `PROVEN`. Arithmetic bounds, access-control reachability, and specific
invariants (e.g. "total shares never exceed total assets") are tractable with
Halmos/hevm/Certora. Supply-chain risk, MEV/front-running, and off-chain/
custodial questions are inherently empirical — cap those at `VERIFIED-LIVE` /
`VERIFIED-SOURCE` and say so; do not stretch the word "proven" to cover them.
