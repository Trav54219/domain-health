#!/usr/bin/env node
// Check sending domains from the command line or a scheduled job.
//
//   node cli.mjs acme.com acme-mail.com
//   node cli.mjs --file domains.txt --system-dns   # also checks Spamhaus DBL + SURBL
//   node cli.mjs --file domains.txt --json
//   SLACK_WEBHOOK_URL=... node cli.mjs --file domains.txt --slack
//
// Exit code 1 when any domain has a failing check, so a CI job goes red.
import { readFileSync } from "node:fs";
import { promises as dns } from "node:dns";
import { checkDomain, dohResolver, rdapLookup } from "./core.js";

const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const value = (f) => (args.includes(f) ? args[args.indexOf(f) + 1] : null);

let domains = args.filter((a, i) => !a.startsWith("--") && !["--file", "--selector"].includes(args[i - 1]));
if (value("--file")) {
  domains.push(...readFileSync(value("--file"), "utf8").split(/\r?\n/).map((l) => l.replace(/#.*/, "").trim()).filter(Boolean));
}
if (!domains.length) {
  console.error("usage: node cli.mjs <domain...> [--file domains.txt] [--selector s] [--system-dns] [--json] [--slack]");
  process.exit(2);
}

// Blocklists only answer resolvers they trust, so they go through the system resolver.
const blocklist = flag("--system-dns")
  ? async (name) => {
      try {
        return await dns.resolve4(name);
      } catch (e) {
        return e.code === "ENOTFOUND" || e.code === "ENODATA" ? [] : null;
      }
    }
  : null;

const resolve = dohResolver();
const selectors = value("--selector") ? value("--selector").split(",") : [];
const results = [];
for (const d of domains) results.push(await checkDomain(d, { resolve, rdap: rdapLookup, blocklist, selectors }));

const ICON = { pass: "ok  ", warn: "WARN", fail: "FAIL", unknown: "  ? " };
if (flag("--json")) {
  console.log(JSON.stringify(results, null, 2));
} else {
  for (const r of results) {
    console.log(`\n${ICON[r.status]} ${r.domain}${r.provider ? `  (${r.provider})` : ""}`);
    for (const c of r.checks) {
      console.log(`  ${ICON[c.status]} ${c.label.padEnd(11)} ${c.summary}`);
      if (c.fix && c.status !== "pass") console.log(`       ${"".padEnd(11)} fix: ${c.fix}`);
    }
  }
}

const bad = results.filter((r) => r.status === "fail");
if (flag("--slack") && process.env.SLACK_WEBHOOK_URL && results.some((r) => r.status === "fail" || r.status === "warn")) {
  const lines = results
    .filter((r) => r.status === "fail" || r.status === "warn")
    .map((r) => `*${r.domain}* ${r.status.toUpperCase()}: ` + r.checks.filter((c) => c.status === "fail" || c.status === "warn").map((c) => `${c.label}: ${c.summary}`).join(" | "));
  await fetch(process.env.SLACK_WEBHOOK_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text: `Domain health: ${bad.length} failing, ${results.length} checked\n${lines.join("\n")}` }),
  });
}
process.exit(bad.length ? 1 : 0);
