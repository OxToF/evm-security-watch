# EVM Watchdog scan backend

Sells the `bin/scan.mjs` report for **USDG on Robinhood Chain** (chain 4663), and
to x402 agents for **USDC on Base** (chain 8453).
Zero runtime dependencies (Node `http` + `fetch`).

## Flows

```
Web    POST /scan {repo,email}            -> jobId + payment terms (unique amount)
       POST /pay/verify {jobId,txHash}    -> on-chain check -> scan -> email
Agent  POST /agent/scan {repo[,email]}    -> 402, x402-style `accepts`, accessToken (once)
       POST /agent/scan {jobId,txHash}    -> on-chain check -> scan
       GET  /agent/jobs/:id[/report.{json,md,html}]   (Bearer accessToken)
       POST /agent/scan {repo} + PAYMENT-SIGNATURE -> x402 v2, USDC on Base, 200 + job
       GET  /skill.md                     -> the manual an agent reads
Other  GET /pay/config · GET /jobs/:id · GET /health
Admin  POST /confirm {jobId} · GET /admin/jobs   (Bearer ADMIN_TOKEN)
```

## How a payment is tied to a job

An EVM transfer carries no memo and its hash is public once mined. Each quote
therefore gets a **unique amount** (price + 1..99 999 base units, i.e. at most
0.099999 USDG), never shared by two open quotes. A payment is accepted only if
the receipt succeeded and holds a `Transfer` log of **exactly** that amount, from
the canonical USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`, never matched by
ticker: the chain is full of fake "Global Dollar (USDG)" tokens), to the merchant,
in a block mined after the quote. The RPC's chain id is checked first.
Quotes expire after `QUOTE_TTL_HOURS` (24); an amount stays reserved for twice
that. A tx hash pays for one job only. Logs are read rather than `tx.to`, so a
smart-wallet payment works.

## x402 on Base

No x402 facilitator settles on Robinhood Chain, so an agent paying the standard
way could not reach the USDG quote, and no discovery catalog (Bazaar) would list
it. The agent 402 therefore also carries a `PAYMENT-REQUIRED` header: exactly
the price in USDC on Base, with its EIP-712 domain (`USD Coin`, `2`) and the
`bazaar` discovery extension. The client resends with `PAYMENT-SIGNATURE` (a
signed EIP-3009 authorization); the server verifies and settles it through the
facilitator, **always against terms rebuilt on the server**, never the client's
echo, then re-reads the settlement receipt on Base with the same exact-amount
check as USDG. The job is created only once paid. The authorization's one-time
nonce is what stops a replay (no unique amount needed); a signature in flight or
already credited is refused.

## Environment

| Var | Purpose |
|---|---|
| `MERCHANT_WALLET` | 0x address receiving USDG (required to take payments) |
| `EVM_RPC_URL` | Robinhood Chain RPC (default: the public one, rate-limited; use a provider in prod) |
| `FACILITATOR_URL` | x402 v2 facilitator for USDC on Base (default `https://facilitator.payai.network`, free tier, no key; `off` keeps only USDG) |
| `BASE_RPC_URL` | Base RPC used to re-check each x402 settlement on-chain (default `https://mainnet.base.org`; a provider in prod) |
| `SCAN_PRICE_USD` | base price in USDG (default 69) |
| `QUOTE_TTL_HOURS` | quote lifetime (default 24) |
| `PUBLIC_BASE_URL` | absolute base for agent-facing URLs and `/skill.md` |
| `ADMIN_TOKEN` | bearer for `/confirm` and `/admin/jobs` |
| `RESEND_API_KEY` + `MAIL_FROM` | email delivery; without them emails go to `server/deliveries/` |
| `ALLOW_ORIGIN` | CORS origin of the landing (default `*`) |
| `SUPPORT_EMAIL` | shown when a paid quote has expired |
| `JOBS_FILE`, `REPORTS_DIR` | job store and agent reports (default `server/data/`) |
| `GITHUB_TOKEN` | lifts GitHub's anonymous limit for the scanner |

## Tests

`node --test server/server.test.mjs` (offline, fake RPC).
