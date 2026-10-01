// PayAI facilitator authentication: a short-lived EdDSA JWT signed with the
// merchant API key, sent as a Bearer token. Without a key, requests stay on the
// public shared lane (the free tier). With one, PayAI never falls back to
// anonymous: a bad key fails every payment, so a misconfiguration must fail at
// boot, not at the first customer.
// https://docs.payai.network/x402/facilitators/authentication
import { createPrivateKey, sign, randomUUID } from "node:crypto";

const b64url = (buf) => Buffer.from(buf).toString("base64url");

export class PayAIAuth {
  // Throws when only one half is set, or when the secret is not an Ed25519 key.
  static fromEnv(env = process.env) {
    const id = env.PAYAI_API_KEY_ID, secret = env.PAYAI_API_KEY_SECRET;
    if (!id && !secret) return null;
    if (!id || !secret) throw new Error("set both PAYAI_API_KEY_ID and PAYAI_API_KEY_SECRET, or neither");
    return new PayAIAuth(id, secret);
  }

  constructor(keyId, secret, { ttlSec = 120, now = () => Date.now() } = {}) {
    const der = Buffer.from(String(secret).trim().replace(/^payai_sk_/, ""), "base64");
    let key;
    try { key = createPrivateKey({ key: der, format: "der", type: "pkcs8" }); }
    catch { throw new Error("PAYAI_API_KEY_SECRET is not a base64 PKCS#8 key"); }
    if (key.asymmetricKeyType !== "ed25519") throw new Error("PAYAI_API_KEY_SECRET is not an Ed25519 key");
    Object.assign(this, { keyId: String(keyId), key, ttlSec, now });
    this._jwt = null;
    this._exp = 0;
  }

  // Cached, refreshed 30 s before it expires.
  token() {
    const t = Math.floor(this.now() / 1000);
    if (this._jwt && t < this._exp - 30) return this._jwt;
    const head = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: this.keyId }));
    const body = b64url(JSON.stringify({ sub: this.keyId, iss: "payai-merchant", iat: t, exp: t + this.ttlSec, jti: randomUUID() }));
    const input = `${head}.${body}`;
    this._jwt = `${input}.${b64url(sign(null, Buffer.from(input), this.key))}`;
    this._exp = t + this.ttlSec;
    return this._jwt;
  }

  headers() { return { authorization: `Bearer ${this.token()}` }; }

  // For logs: which key, never the secret.
  label() { return `key ${this.keyId.slice(0, 6)}…`; }
}
