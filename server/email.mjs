// Report delivery. Uses the Resend HTTP API when RESEND_API_KEY is set (zero deps,
// pure fetch); otherwise falls back to writing the email to server/deliveries/ so
// the flow is fully testable with no email provider. Swap in Postmark/SES/SMTP by
// editing sendReport only.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export async function sendReport({ to, subject, html, text, attachments = [], fetchImpl = globalThis.fetch, log = console.log }) {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.MAIL_FROM || "scan@soladrome.finance";
  if (!key) {
    const dir = process.env.DELIVERIES_DIR || "server/deliveries";
    mkdirSync(dir, { recursive: true });
    const safe = to.replace(/[^A-Za-z0-9_.@-]/g, "_");
    const p = join(dir, `${Date.now()}-${safe}.html`);
    writeFileSync(p, `<!-- to:${to} subject:${subject} -->\n${html}`);
    for (const a of attachments) writeFileSync(join(dir, a.filename), Buffer.from(a.content, "base64"));
    log(`[email] DEV MODE (no RESEND_API_KEY) -> wrote ${p}`);
    return { devMode: true, path: p };
  }
  const res = await fetchImpl("https://api.resend.com/emails", {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({ from, to, subject, html, text, attachments }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${await res.text()}`);
  log(`[email] sent to ${to}`);
  return await res.json();
}
