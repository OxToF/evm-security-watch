// A dead-simple sequential queue: scans are CPU/network heavy, so run one at a
// time. Enqueue returns nothing; the task runs in the background and is expected
// to persist its own result/status.
export class Queue {
  constructor() { this.tasks = []; this.running = false; }
  enqueue(task) { this.tasks.push(task); this._drain(); }
  async _drain() {
    if (this.running) return;
    this.running = true;
    while (this.tasks.length) {
      const t = this.tasks.shift();
      try { await t(); } catch (e) { console.error("[queue] task failed:", e.message); }
    }
    this.running = false;
  }
}
