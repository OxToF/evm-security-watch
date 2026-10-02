// Request log: one JSON line per request, appended to a file on the volume and
// echoed to stdout (fly logs keeps only the last few hours). It answers the one
// question the payment ledger cannot: did anyone call, and where did they stop?
//
// Nothing secret goes in: ids and report tokens in the path are replaced by
// placeholders, the caller IP is a salted hash (counts unique callers, never
// names one), the query string and bodies are dropped.
import { appendFileSync, readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomBytes, createHash } from "node:crypto";

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

// "/r/<uuid>/<token>" -> "/r/:id/:token", "/agent/jobs/<uuid>/report.md" -> "/agent/jobs/:id/report.md"
export function routeOf(pathname) {
  let p = String(pathname || "/").slice(0, 200).replace(UUID, ":id");
  if (p.startsWith("/r/")) p = p.replace(/^\/r\/[^/]+\/[^/]+/, "/r/:id/:token");
  return p;
}

// Load balancer health checks would drown everything else.
const SKIP = new Set(["/health"]);

export class Traffic {
  constructor(file, { echo = true } = {}) {
    this.file = file;
    this.echo = echo;
    mkdirSync(dirname(file), { recursive: true });
    const saltFile = join(dirname(file), "traffic-salt");
    if (!existsSync(saltFile)) writeFileSync(saltFile, randomBytes(16).toString("hex"));
    this.salt = readFileSync(saltFile, "utf8").trim();
  }

  caller(ip) { return createHash("sha256").update(this.salt + ip).digest("hex").slice(0, 12); }

  // Call at the top of the request handler: logs once the response is sent.
  watch(req, res, ip) {
    const t0 = Date.now();
    const route = routeOf(new URL(req.url, "http://x").pathname);
    if (req.method === "OPTIONS" || SKIP.has(route)) return;
    res.on("finish", () => {
      let ref = null;
      try { ref = req.headers.referer ? new URL(req.headers.referer).host : null; } catch {}
      this.record({
        t: new Date(t0).toISOString(),
        m: req.method,
        route,
        status: res.statusCode,
        ms: Date.now() - t0,
        caller: this.caller(ip),
        ua: String(req.headers["user-agent"] || "").slice(0, 120) || null,
        ref,
        // Carries an x402 payment proof. The memo flow (proof in the body) is not
        // flagged: the chain is the ledger for payments, see revenue.mjs.
        pay: Boolean(req.headers["payment-signature"] || req.headers["x-payment"]) || undefined,
      });
    });
  }

  record(line) {
    const s = JSON.stringify(line);
    try { appendFileSync(this.file, s + "\n"); } catch (e) { console.error(`[traffic] ${e.message}`); }
    if (this.echo) console.log(`[req] ${s}`);
  }

  // Aggregate since `sinceMs`: per route and status, unique callers, the agents' funnel.
  summary(sinceMs = 0) {
    const lines = existsSync(this.file) ? readFileSync(this.file, "utf8").split("\n") : [];
    const routes = {}, callers = new Set(), agents = {}, uas = {};
    let total = 0, quoted = 0, payAttempts = 0, paid = 0, first = null, last = null;
    for (const l of lines) {
      if (!l) continue;
      let r; try { r = JSON.parse(l); } catch { continue; }
      if (Date.parse(r.t) < sinceMs) continue;
      total++;
      first ??= r.t; last = r.t;
      callers.add(r.caller);
      const k = `${r.m} ${r.route}`;
      (routes[k] ??= {})[r.status] = (routes[k][r.status] || 0) + 1;
      if (r.ua) uas[r.ua] = (uas[r.ua] || 0) + 1;
      if (r.m === "POST" && r.route.startsWith("/agent/")) {
        (agents[r.caller] ??= { calls: 0, quoted: 0, paid: 0 }).calls++;
        if (r.status === 402) { quoted++; agents[r.caller].quoted++; }
        if (r.pay) payAttempts++;
        if (r.pay && r.status < 300) { paid++; agents[r.caller].paid++; }
      }
    }
    const topUa = Object.entries(uas).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([ua, n]) => ({ ua, n }));
    return { since: new Date(sinceMs).toISOString(), first, last, total, uniqueCallers: callers.size,
      agentFunnel: { quoted, payAttempts, paid, callers: Object.keys(agents).length }, routes, topUserAgents: topUa };
  }
}
