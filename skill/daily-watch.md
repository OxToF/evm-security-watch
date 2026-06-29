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

- `RAS` (nothing relevant) — with the list of sources swept.
- Otherwise, per finding: technique, affected surface, `file:line`, estimated
  severity, and a **proposed** fix.

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
# Static analysis
slither .                          # reference detector (Crytic / Trail of Bits)
aderyn .                           # Rust detector (Cyfrin), fast
myth analyze <contract>            # Mythril — symbolic execution
semgrep --config p/smart-contracts # Semgrep rules

# Fuzzing / invariants (if a Foundry suite is present)
forge test                         # unit tests
forge test --match-test invariant  # invariant testing
echidna <contract> --config echidna.yaml

# On-chain (deployed contract)
# Block explorer API: watch events, admin txns, proxy upgrades
# Tenderly: simulate / replay suspicious transactions
# scripts/call.js: selectors, eth_call, bytecode size/hash, storage slots
```
