# EVM / Solidity vulnerability classes

> The checklist to re-confront code against, every watch pass. Each row: what to
> look for, how to detect it (grep / static lead), and the safe pattern. A hit is
> a **lead, not a finding** — confirm by reading the source.

## 1. Reentrancy

- **What** — classic, cross-function, cross-contract, and **read-only** (a view
  read of inconsistent state during a callback).
- **Detect** — external call / `transfer` / `call{value:}` before state updates;
  absence of `nonReentrant`; ERC777/ERC1155 hooks.
- **Safe** — checks-effects-interactions ordering + `nonReentrant`; for read-only,
  guard the view or snapshot state.

## 2. Access control

- **What** — sensitive function missing a modifier; unprotected `initialize()`;
  mis-assigned role; `tx.origin` instead of `msg.sender`.
- **Detect** — grep `function` bodies that mutate state / move funds with no
  `onlyOwner` / `onlyRole` / `require(msg.sender …)`; grep `tx.origin`.
- **Safe** — explicit modifier on every privileged path; `initializer` modifier;
  role checks via AccessControl.

## 3. Proxy / upgradeability

- **What** — implementation left uninitialized (front-run of `initialize`),
  `_authorizeUpgrade` open (UUPS), storage-layout collision after upgrade, selector
  clash (Transparent), `delegatecall` to arbitrary code.
- **Detect** — grep `delegatecall`, `upgradeToAndCall`, `_authorizeUpgrade`,
  missing `_disableInitializers()` in the implementation constructor.
- **Safe** — `_disableInitializers()` in constructor; access-gated
  `_authorizeUpgrade`; append-only storage layout / storage gaps.

## 4. Arithmetic

- **What** — `unchecked` blocks; `uint256→uintN` downcasts that truncate;
  division before multiplication (precision loss); rounding in the user's favour
  (must favour the protocol).
- **Detect** — grep `unchecked`, `uint128(`, `uint64(`, `/` near `*`.
- **Safe** — keep checked math (or justify each `unchecked`); multiply before
  divide; round against the user; use `SafeCast`.

## 5. Oracle

- **What** — spot price manipulable by flash loan; TWAP window too short; missing
  staleness check / circuit breaker; L2 sequencer down → frozen oracle.
- **Detect** — grep oracle reads (`latestRoundData`, `getReserves`, `slot0`);
  check for `updatedAt` / `answeredInRound` validation and sequencer-uptime feed.
- **Safe** — TWAP / median; staleness + bounds checks; L2 sequencer-uptime guard.

## 6. AMM / vault (ERC4626)

- **What** — first-deposit inflation / donation attack; missing
  `MINIMUM_LIQUIDITY`; cumulative rounding (cf. the Balancer rounding exploit).
- **Detect** — `convertToShares` / `convertToAssets` without virtual-shares/offset;
  direct `balanceOf(address(this))` used as the accounting source.
- **Safe** — virtual shares / dead-shares offset; internal accounting decoupled
  from raw balance.

## 7. Signatures

- **What** — replay (no nonce / domain), `ecrecover` malleability (high-half `s`),
  missing `deadline`, permit phishing.
- **Detect** — grep `ecrecover`, `permit`, EIP-712 `DOMAIN_SEPARATOR`; check nonce
  increment and `s` bounds.
- **Safe** — EIP-712 with chainId + nonce + deadline; ECDSA library that rejects
  malleable `s`.

## 8. Non-standard tokens

- **What** — fee-on-transfer, rebasing, missing `bool` return → silent failure;
  ERC777/ERC1155 hooks enabling reentrancy.
- **Detect** — grep raw `.transfer(` / `.transferFrom(` / `.approve(` on `IERC20`.
- **Safe** — `SafeERC20`; measure balance deltas for fee-on-transfer; account for
  hook reentrancy.

## 9. Denial of service

- **What** — unbounded loop; push-payment that can revert (prefer pull); gas
  griefing; dependence on `block.gaslimit`.
- **Detect** — loops over user-growable arrays; `for` over storage; external call
  inside a loop.
- **Safe** — pull-over-push; bound iteration; isolate external calls.

## 10. MEV / front-running

- **What** — sandwichable swaps without slippage; on-chain secret reveal;
  ordering-dependence.
- **Detect** — swap calls with no `minOut` / `amountOutMin`; commit-reveal absent.
- **Safe** — user-supplied slippage bounds; commit-reveal; deadline.

## 11. L2 / rollup specifics

- **What** — `block.number` ≠ wall-clock on some L2s; L1→L2 message address
  aliasing; finality assumptions; sequencer downtime.
- **Detect** — time/block-based logic; cross-domain message handlers.
- **Safe** — use `block.timestamp` appropriately; handle aliased senders;
  sequencer-uptime feed for time-sensitive logic.

## 12. Init / deployment

- **What** — missing `_disableInitializers()` in the implementation constructor;
  immutable vs. storage constants; deprecated `selfdestruct`.
- **Detect** — implementation contracts with an `initialize` but no constructor
  guard.
- **Safe** — disable initializers in the constructor; verify the deployed contract
  on the explorer.

## 13. Fund-flow / accounting

- **What** — internal accounting drifting from real balance; double-spend / replay
  of a payment; opaque `withdraw` controlled by a single key.
- **Detect** — `withdraw` / `transferFrom` paths; compare bookkeeping vars to
  `balanceOf`.
- **Safe** — single source of truth for balances; replay protection; privileged
  withdrawal behind multisig + timelock.

## 14. Supply chain

- **What** — OpenZeppelin (or other lib) version with an open advisory; compromised
  npm dependency; Solidity compiler version with a known bug.
- **Detect** — cross-check `package.json` / lockfile against the GitHub Advisory DB;
  check `solc` against the [official known-bugs list](https://docs.soliditylang.org/en/latest/bugs.html).
- **Safe** — pin and update to patched versions; review transitive deps; avoid
  compiler versions with relevant known bugs.
