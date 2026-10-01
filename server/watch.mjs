// Paid watches: re-check a contract or a lockfile on a schedule and POST a signed
// webhook when something that matters changes. State lives in its own JSON store.
//
// The webhook URL is caller-supplied, so delivery is the SSRF surface of this
// server: https only, every resolved address must be public, no redirects.
import { createHmac, randomBytes } from "node:crypto";
import { lookup } from "node:dns/promises";
import { lookup as lookupCb } from "node:dns";
import { isIP } from "node:net";
import http from "node:http";
import https from "node:https";

// --- what counts as a change ---------------------------------------------------------
// Only what an agent acts on: the live code, who can replace it, who owns the contract,
// whether the live code is still public; for a lockfile, an advisory that was not there.
const ctrl = (c) => {
  let f = c;
  while (f && f.kind === "owned-contract") f = f.ownedBy;
  return f ? { kind: f.kind, address: f.address, threshold: f.threshold ?? null, owners: f.owners ?? null, minDelaySeconds: f.minDelaySeconds ?? null } : null;
};
export function contractSnapshot(r) {
  return {
    isContract: !!r.isContract,
    proxy: r.proxy ? r.proxy.kind : null,
    implementation: r.implementation || null,
    upgradeController: ctrl(r.upgradeController),
    owner: ctrl(r.owner),
    implementationVerified: r.verified ? r.verified.implementation ?? null : null,
  };
}
function controllerEvents(name, a, b) {
  if (!a && !b) return [];
  if (!a || !b || a.address !== b.address || a.kind !== b.kind)
    return [{ type: `${name}-changed`, severity: b && b.kind === "single-key" ? "high" : "medium", text: `${name === "upgrade-controller" ? "Upgrade controller" : "Owner"} changed: ${a ? `${a.kind} ${a.address}` : "none"} → ${b ? `${b.kind} ${b.address}` : "none"}`, before: a, after: b }];
  if (a.kind === "safe" && (a.threshold !== b.threshold || a.owners !== b.owners))
    return [{ type: `${name}-safe-changed`, severity: b.threshold <= 1 ? "high" : "medium", text: `Safe rules changed: ${a.threshold} of ${a.owners} → ${b.threshold} of ${b.owners}`, before: a, after: b }];
  if (a.kind === "timelock" && a.minDelaySeconds !== b.minDelaySeconds)
    return [{ type: `${name}-timelock-changed`, severity: b.minDelaySeconds < a.minDelaySeconds ? "high" : "medium", text: `Timelock delay changed: ${a.minDelaySeconds} s → ${b.minDelaySeconds} s`, before: a, after: b }];
  return [];
}
export function diffContract(before, after) {
  const events = [];
  if (before.isContract && !after.isContract) return [{ type: "code-removed", severity: "high", text: "There is no longer contract code at this address." }];
  if (before.implementation !== after.implementation || before.proxy !== after.proxy)
    events.push({ type: "implementation-changed", severity: "high", text: `The live code changed: ${before.proxy || "not a proxy"} ${before.implementation || ""} → ${after.proxy || "not a proxy"} ${after.implementation || ""}`.replace(/\s+/g, " ").trim(), before: before.implementation, after: after.implementation });
  events.push(...controllerEvents("upgrade-controller", before.upgradeController, after.upgradeController));
  events.push(...controllerEvents("owner", before.owner, after.owner));
  if (before.implementationVerified && before.implementationVerified !== "none" && after.implementationVerified === "none")
    events.push({ type: "verification-lost", severity: "medium", text: "The live implementation has no verified source on Sourcify." });
  return events;
}
export function lockfileSnapshot(advisories) {
  return { advisories: [...new Set(advisories.map((a) => a.id))].sort() };
}
export function diffLockfile(before, after, advisories) {
  const known = new Set(before.advisories);
  return advisories.filter((a) => !known.has(a.id)).map((a) => ({
    type: "new-advisory", severity: /critical|high/i.test(a.severity || "") ? "high" : "medium",
    text: `New advisory ${a.id} affects ${(a.packages || a.crates || []).join(", ")}: ${a.summary || ""}`.trim(), advisory: a,
  }));
}

// --- webhook safety -------------------------------------------------------------------
function privateV4(ip) {
  const [a, b] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
}
export function isPrivateAddress(ip) {
  if (isIP(ip) === 4) return privateV4(ip);
  const v = ip.toLowerCase();
  const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return privateV4(mapped[1]);
  return v === "::" || v === "::1" || /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || /^ff/.test(v);
}
// Throws unless the URL is https and every address its host resolves to is public.
export async function checkWebhookUrl(raw, { allowPrivate = false, resolve = lookup } = {}) {
  let u;
  try { u = new URL(raw); } catch { throw new Error("webhook must be a URL"); }
  if (u.protocol !== "https:" && !(allowPrivate && u.protocol === "http:")) throw new Error("webhook must be https");
  if (u.username || u.password) throw new Error("webhook must not carry credentials");
  if (raw.length > 500) throw new Error("webhook URL is too long");
  if (allowPrivate) return u;
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const addrs = isIP(host) ? [{ address: host }] : await resolve(host, { all: true }).catch(() => []);
  if (!addrs.length) throw new Error("webhook host does not resolve");
  if (addrs.some((a) => isPrivateAddress(a.address))) throw new Error("webhook must point to a public address");
  return u;
}

// POST that resolves the host itself and refuses a private address at connect time, so
// a DNS answer that changes between the check and the connection (rebinding) does not
// get through. Node's http client never follows redirects on its own.
export function guardedPost(url, headers, body, { allowPrivate = false, timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const guardLookup = (host, opts, cb) => lookupCb(host, { ...opts, all: true }, (err, addrs) => {
      if (err) return cb(err);
      const list = Array.isArray(addrs) ? addrs : [{ address: addrs, family: opts.family || 4 }];
      if (!allowPrivate && list.some((a) => isPrivateAddress(a.address))) return cb(new Error("webhook resolved to a private address"));
      if (opts.all) return cb(null, list);
      cb(null, list[0].address, list[0].family);
    });
    const req = lib.request(u, { method: "POST", headers: { ...headers, "content-length": Buffer.byteLength(body) }, lookup: guardLookup, timeout: timeoutMs }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode }));
    });
    req.on("timeout", () => req.destroy(new Error("webhook timed out")));
    req.on("error", reject);
    req.end(body);
  });
}

export const sign = (secret, body) => "sha256=" + createHmac("sha256", secret).update(body).digest("hex");

// --- the watcher ----------------------------------------------------------------------
// check(watch) -> { snapshot, events } re-reads the target; deliver is fetch-like.
export class Watcher {
  constructor({ store, check, post = guardedPost, allowPrivate = false, intervalMs = 60 * 60 * 1000, tickMs = 60 * 1000, log = () => {} }) {
    Object.assign(this, { store, check, post, allowPrivate, intervalMs, tickMs, log });
    this.running = false;
  }
  start() {
    this.timer = setInterval(() => this.tick().catch((e) => this.log(`[watch] tick: ${e.message}`)), this.tickMs);
    this.timer.unref?.();
  }
  stop() { clearInterval(this.timer); }

  async tick(now = Date.now()) {
    if (this.running) return;
    this.running = true;
    try {
      const due = this.store.list((w) => w.status === "active" && (!w.lastCheckedAt || now - Date.parse(w.lastCheckedAt) >= this.intervalMs));
      for (const w of due) {
        if (now >= Date.parse(w.expiresAt)) { this.store.update(w.id, { status: "expired" }); continue; }
        await this.checkOne(w, now);
      }
    } finally { this.running = false; }
  }

  async checkOne(w, now = Date.now()) {
    let out;
    try { out = await this.check(w); }
    catch (e) {
      // A failed lookup is not a change: try again next round, and say so if it persists.
      const failures = (w.checkFailures || 0) + 1;
      this.store.update(w.id, { lastCheckedAt: new Date(now).toISOString(), checkFailures: failures, lastError: String(e.message).slice(0, 200) });
      return;
    }
    const patch = { lastCheckedAt: new Date(now).toISOString(), checkFailures: 0, lastError: null };
    if (!out.events.length) { this.store.update(w.id, patch); return; }
    const delivered = await this.deliver(w, out.events, now);
    const events = [...(w.events || []), ...out.events.map((e) => ({ ...e, at: new Date(now).toISOString(), delivered }))].slice(-50);
    // The baseline moves even when delivery failed: the events stay readable on GET,
    // and an agent is not paged twice for the same change.
    this.store.update(w.id, { ...patch, snapshot: out.snapshot, events });
  }

  async deliver(w, events, now) {
    const body = JSON.stringify({ watchId: w.id, target: w.targetSummary, events, at: new Date(now).toISOString() });
    try { await checkWebhookUrl(w.webhook, { allowPrivate: this.allowPrivate }); }
    catch (e) { this.log(`[watch] ${w.id} webhook refused: ${e.message}`); return false; }
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const r = await this.post(w.webhook, { "content-type": "application/json", "x-watchdog-signature": sign(w.secret, body), "x-watchdog-watch": w.id }, body, { allowPrivate: this.allowPrivate });
        if (r.status >= 200 && r.status < 300) return true;
      } catch {}
      await new Promise((s) => setTimeout(s, 500 * (attempt + 1)));
    }
    return false;
  }
}

export const newSecret = () => randomBytes(32).toString("base64url");
