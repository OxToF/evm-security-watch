// Minimal file-backed job store. No DB dependency — fine for the volume an MVP
// funnel sees. One JSON file, loaded on boot, written on every change.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID, randomInt } from "node:crypto";

export class Store {
  constructor(file) {
    this.file = file;
    this.jobs = {};
    if (existsSync(file)) {
      try { this.jobs = JSON.parse(readFileSync(file, "utf8")); } catch { this.jobs = {}; }
    } else {
      mkdirSync(dirname(file), { recursive: true });
    }
  }
  _save() { writeFileSync(this.file, JSON.stringify(this.jobs, null, 2) + "\n"); }
  create(fields) {
    const id = randomUUID();
    const now = new Date().toISOString();
    this.jobs[id] = { id, status: "pending_payment", createdAt: now, updatedAt: now, ...fields };
    this._save();
    return this.jobs[id];
  }
  get(id) { return this.jobs[id] || null; }
  update(id, patch) {
    if (!this.jobs[id]) return null;
    this.jobs[id] = { ...this.jobs[id], ...patch, updatedAt: new Date().toISOString() };
    this._save();
    return this.jobs[id];
  }
  list(filter) {
    const all = Object.values(this.jobs).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return filter ? all.filter(filter) : all;
  }
  // Replay protection: has this payment tx already been credited to a job?
  findByPayment(txHash) {
    const h = String(txHash || "").toLowerCase();
    return (h && Object.values(this.jobs).find((j) => j.paymentTx === h)) || null;
  }
  // A quoted amount no other recent unpaid quote holds: base + 1..spread-1 base
  // units. The amount is what binds an EVM payment to its job, so two open quotes
  // must never share one. Quotes expire after `ttlMs`; an amount stays reserved
  // for twice that, so a late payment cannot land on a newer job.
  uniqueAmount(base, spread, ttlMs, now = Date.now()) {
    const taken = new Set(Object.values(this.jobs)
      .filter((j) => j.amountBase && j.status === "pending_payment" && now - Date.parse(j.createdAt) < 2 * ttlMs)
      .map((j) => j.amountBase));
    for (let i = 0; i < 64; i++) {
      const a = (BigInt(base) + BigInt(randomInt(1, spread))).toString();
      if (!taken.has(a)) return a;
    }
    throw new Error("no free quote amount, try again later");
  }
}
