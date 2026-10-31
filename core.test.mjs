import { test } from "node:test";
import assert from "node:assert/strict";
import { checkDomain, checkSpf, checkBlocklists, normalizeDomain, spfLookups } from "./core.js";

// A fake DNS: keys are "name TYPE".
const zone = (records) => async (name, type) => records[`${name} ${type}`] || [];

test("normalizeDomain strips scheme, path, email and www", () => {
  assert.equal(normalizeDomain("https://www.Acme.com/pricing"), "acme.com");
  assert.equal(normalizeDomain("jane@acme.co"), "acme.co");
  assert.equal(normalizeDomain("not a domain"), null);
});

test("SPF lookups are counted through nested includes", async () => {
  const r = zone({
    "a.com TXT": ["v=spf1 include:b.com mx ~all"],
    "b.com TXT": ["v=spf1 include:c.com a ~all"],
    "c.com TXT": ["v=spf1 ip4:1.2.3.4 ~all"],
  });
  assert.equal((await spfLookups("a.com", r)).count, 4);
});

test("SPF over 10 lookups fails", async () => {
  const records = { "a.com TXT": [`v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:i${i}.com`).join(" ")} -all`] };
  for (let i = 0; i < 11; i++) records[`i${i}.com TXT`] = ["v=spf1 -all"];
  const c = await checkSpf("a.com", zone(records), null);
  assert.equal(c.status, "fail");
});

test("two SPF records fail, +all fails, missing provider include warns", async () => {
  assert.equal((await checkSpf("a.com", zone({ "a.com TXT": ["v=spf1 -all", "v=spf1 ~all"] }), null)).status, "fail");
  assert.equal((await checkSpf("a.com", zone({ "a.com TXT": ["v=spf1 +all"] }), null)).status, "fail");
  const google = { name: "Google Workspace", spf: "_spf.google.com" };
  assert.equal((await checkSpf("a.com", zone({ "a.com TXT": ["v=spf1 include:sendgrid.net ~all"] }), google)).status, "warn");
});

test("a healthy Google Workspace domain passes, and a missing DMARC fails with a fix", async () => {
  const healthy = zone({
    "acme.com MX": ["1 smtp.google.com."],
    "acme.com TXT": ["v=spf1 include:_spf.google.com ~all"],
    "_spf.google.com TXT": ["v=spf1 ip4:1.2.3.4 ~all"],
    "google._domainkey.acme.com TXT": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"],
    "_dmarc.acme.com TXT": ["v=DMARC1; p=quarantine; rua=mailto:d@acme.com"],
    "acme.com A": ["1.2.3.4"],
  });
  const ok = await checkDomain("acme.com", { resolve: healthy });
  assert.equal(ok.status, "pass");
  assert.equal(ok.provider, "Google Workspace");

  const noDmarc = zone({ "acme.com MX": ["1 smtp.google.com."], "acme.com TXT": ["v=spf1 include:_spf.google.com ~all"], "acme.com A": ["1.2.3.4"] });
  const bad = await checkDomain("acme.com", { resolve: noDmarc });
  const dmarc = bad.checks.find((c) => c.id === "dmarc");
  assert.equal(dmarc.status, "fail");
  assert.match(dmarc.fix, /_dmarc\.acme\.com: v=DMARC1; p=none/);
});

test("blocklist: listed fails, refused is unknown, never treated as clean", async () => {
  const listed = await checkBlocklists("x.com", async (n) => (n.endsWith("dbl.spamhaus.org") ? ["127.0.1.2"] : []));
  assert.equal(listed.status, "fail");
  const refused = await checkBlocklists("x.com", async (n) => (n.endsWith("dbl.spamhaus.org") ? ["127.255.255.254"] : ["127.0.0.254"]));
  assert.equal(refused.status, "unknown");
  const browser = await checkBlocklists("x.com", null);
  assert.equal(browser.status, "unknown");
});
