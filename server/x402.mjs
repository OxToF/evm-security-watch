// x402 v2 over HTTP, settled by a facilitator (PayAI by default: free tier, no key).
//
// Why a second rail next to USDG on Robinhood Chain: no x402 facilitator settles
// on Robinhood Chain (chain 4663 is absent from PayAI's /supported), so an agent
// paying the standard way cannot reach the USDG quote, and a discovery catalog
// (the Bazaar) never lists it. USDC on Base is what those agents hold. The client
// signs an EIP-3009 transferWithAuthorization; the facilitator submits it and
// pays the gas; the one-time nonce inside the authorization is what stops a
// replay, so no unique amount is needed on this rail.
//
// Zero deps: fetch + Buffer.

export const BASE_MAINNET = "eip155:8453";
// Canonical USDC on Base. `name`/`version` are its EIP-712 domain (read on-chain:
// name() = "USD Coin"); a client signs against them, so they must be exact.
export const BASE_USDC = {
  address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  name: "USD Coin",
  version: "2",
  decimals: 6,
  symbol: "USDC",
  chainId: 8453,
};

export const encodeHeader = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64");
export function decodeHeader(value) {
  try { return JSON.parse(Buffer.from(String(value), "base64").toString("utf8")); }
  catch { return null; }
}

export class Facilitator {
  constructor({ url, fetchImpl = globalThis.fetch }) {
    this.url = url.replace(/\/$/, "");
    this.fetch = fetchImpl;
  }

  async _post(path, body) {
    const res = await this.fetch(`${this.url}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    if (!json) throw new Error(`facilitator ${path} ${res.status}: ${text.slice(0, 200)}`);
    return json;
  }

  verify(paymentPayload, paymentRequirements) {
    return this._post("/verify", { x402Version: 2, paymentPayload, paymentRequirements });
  }

  settle(paymentPayload, paymentRequirements) {
    return this._post("/settle", { x402Version: 2, paymentPayload, paymentRequirements });
  }
}

// The `bazaar` extension: what a discovery catalog shows an agent about this
// endpoint. Same-document JSON Schema only (the spec forbids external $ref).
export function bazaarExtension({ exampleRepo, base }) {
  return {
    info: {
      input: { type: "http", method: "POST", bodyType: "json", body: { repo: exampleRepo } },
      output: {
        type: "json",
        example: {
          jobId: "8f0c6a2e-1b7d-4c1e-9d3a-2f5e6b7c8d9e",
          status: "paid",
          accessToken: "<shown once, send as Authorization: Bearer>",
          statusUrl: `${base}/agent/jobs/8f0c6a2e-1b7d-4c1e-9d3a-2f5e6b7c8d9e`,
        },
      },
    },
    schema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      properties: {
        input: {
          type: "object",
          properties: {
            type: { type: "string", const: "http" },
            method: { type: "string", enum: ["POST"] },
            bodyType: { type: "string", enum: ["json"] },
            body: {
              type: "object",
              properties: {
                repo: { type: "string", description: "Public GitHub repository URL, https://github.com/<owner>/<repo>" },
                email: { type: "string", description: "Optional. Also email the report here." },
              },
              required: ["repo"],
            },
          },
          required: ["type", "method", "bodyType", "body"],
          additionalProperties: false,
        },
        output: {
          type: "object",
          properties: { type: { type: "string" }, example: { type: "object" } },
          required: ["type"],
        },
      },
      required: ["input"],
    },
  };
}
