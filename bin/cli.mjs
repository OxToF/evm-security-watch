#!/usr/bin/env node
// evm-security-watch CLI.
//   evm-security-watch collect [--out <dir>]
//   evm-security-watch scan <https://github.com/owner/repo> [--out <dir>]
import { runCollect, DEFAULT_PACKAGES } from "./collect.mjs";
import { runScan } from "./scan.mjs";

function parseFlags(argv) {
  const f = { out: "watch-reports", repo: null, local: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") f.out = argv[++i];
    else if (a === "--local") f.local = argv[++i];
    else if (!a.startsWith("--") && !f.repo) f.repo = a;
  }
  return f;
}
function usage() {
  console.log("Usage:");
  console.log("  evm-security-watch collect [--out <dir>]");
  console.log("  evm-security-watch scan <https://github.com/owner/repo> [--out <dir>]");
}
const [cmd, ...rest] = process.argv.slice(2);
const flags = parseFlags(rest);
switch (cmd) {
  case "collect":
    try { await runCollect({ out: flags.out, packages: DEFAULT_PACKAGES }); }
    catch (e) { console.error(`[collect] failed: ${e.message}`); process.exit(1); }
    break;
  case "scan":
    if (!flags.repo && !flags.local) { console.error("scan needs a public repo URL"); process.exit(1); }
    try { await runScan({ repoUrl: flags.repo, localPath: flags.local, out: flags.out === "watch-reports" ? "scan-out" : flags.out }); }
    catch (e) { console.error(`[scan] failed: ${e.message}`); process.exit(1); }
    break;
  case "help": case "--help": case "-h": case undefined:
    usage(); break;
  default:
    console.error(`Unknown command: ${cmd}\n`); usage(); process.exit(1);
}
