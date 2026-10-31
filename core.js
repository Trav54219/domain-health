// Sending-domain health checks. Pure: every DNS answer comes through `resolve`,
// so the same code runs in the browser (DNS over HTTPS), in Node and in tests.
//
//   resolve(name, type) -> Promise<string[]>   (TXT records joined, quotes removed)
//   rdap(domain)        -> Promise<object|null> (optional, for domain age)
//   blocklist(name)     -> Promise<string[]|null> (optional; null = can't check)

export const DKIM_SELECTORS = [
  "google", "selector1", "selector2", "default", "dkim", "mail", "k1", "k2", "k3",
  "s1", "s2", "smtp", "mxvault", "zoho", "zmail", "mandrill", "pm", "mailjet",
  "protonmail", "protonmail2", "protonmail3", "sig1", "fm1", "fm2", "fm3",
  "hs1", "hs2", "cm", "mg", "krs", "everlytickey1", "turbo-smtp", "sendinblue",
];

const SPF_LOOKUP_LIMIT = 10;
const NEW_DOMAIN_DAYS = 30;

const PROVIDERS = [
  { name: "Google Workspace", mx: /(aspmx\.l\.google\.com|smtp\.google\.com|googlemail\.com)\.?$/i, spf: "_spf.google.com" },
  { name: "Microsoft 365", mx: /mail\.protection\.outlook\.com\.?$/i, spf: "spf.protection.outlook.com" },
  { name: "Zoho", mx: /zoho\.(com|eu|in)\.?$/i, spf: "zoho" },
  { name: "Proton", mx: /protonmail\.ch\.?$/i, spf: "_spf.protonmail.ch" },
  { name: "Fastmail", mx: /messagingengine\.com\.?$/i, spf: "spf.messagingengine.com" },
];

export function normalizeDomain(input) {
  let d = String(input || "").trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, "").replace(/^[^@]*@/, "").split(/[/?#:\s]/)[0];
  d = d.replace(/^www\./, "").replace(/\.$/, "");
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) ? d : null;
}

const result = (id, label, status, summary, detail = [], fix = null) => ({ id, label, status, summary, detail, fix });

export async function checkMx(domain, resolve) {
  const mx = (await resolve(domain, "MX")).map((r) => r.split(/\s+/).pop().replace(/\.$/, ""));
  if (!mx.length) return { check: result("mx", "MX", "fail", "No MX records: this domain can't receive replies or bounces."), provider: null, mx };
  const provider = PROVIDERS.find((p) => mx.some((h) => p.mx.test(h))) || null;
  return {
    check: result("mx", "MX", "pass", `${mx.length} MX record${mx.length > 1 ? "s" : ""}${provider ? `, ${provider.name}` : ""}.`, mx),
    provider,
    mx,
  };
}

/** Count the DNS lookups an SPF record costs, following include/redirect. */
export async function spfLookups(domain, resolve, seen = new Set(), depth = 0) {
  if (depth > 10 || seen.has(domain)) return { count: 0, errors: [`loop or depth limit at ${domain}`] };
  seen.add(domain);
  const rec = (await resolve(domain, "TXT")).filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (rec.length !== 1) return { count: 0, errors: rec.length ? [`${domain} has ${rec.length} SPF records`] : [`${domain} has no SPF record`] };
  let count = 0;
  const errors = [];
  for (const term of rec[0].split(/\s+/).slice(1)) {
    const m = term.match(/^[+?~-]?(include|a|mx|ptr|exists|redirect)\b[:=]?(.*)$/i);
    if (!m) continue;
    count += 1;
    const kind = m[1].toLowerCase();
    if ((kind === "include" || kind === "redirect") && m[2]) {
      const sub = await spfLookups(m[2], resolve, seen, depth + 1);
      count += sub.count;
      errors.push(...sub.errors);
    }
  }
  return { count, errors };
}

export async function checkSpf(domain, resolve, provider) {
  const recs = (await resolve(domain, "TXT")).filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (!recs.length) {
    return result("spf", "SPF", "fail", "No SPF record. Receivers can't tell which servers may send for this domain.", [],
      `Add a TXT record at ${domain}: v=spf1 include:${provider?.spf || "<your mail provider's SPF domain>"} ~all`);
  }
  if (recs.length > 1) return result("spf", "SPF", "fail", `${recs.length} SPF records. Receivers treat more than one as an error (permerror).`, recs);
  const spf = recs[0];
  const detail = [spf];
  const all = (spf.match(/\s([+?~-]?)all\b/i) || [])[1];
  const { count, errors } = await spfLookups(domain, resolve);
  detail.push(`${count} of ${SPF_LOOKUP_LIMIT} DNS lookups used.`, ...errors);
  if (count > SPF_LOOKUP_LIMIT) return result("spf", "SPF", "fail", `Needs ${count} DNS lookups; the limit is ${SPF_LOOKUP_LIMIT}, so receivers fail it.`, detail);
  if (all === "+" || (all === "" && /\sall\b/i.test(spf))) return result("spf", "SPF", "fail", "Ends in +all: anyone may send as this domain.", detail);
  if (provider && !spf.toLowerCase().includes(provider.spf)) {
    return result("spf", "SPF", "warn", `Mail is hosted on ${provider.name}, but SPF doesn't include ${provider.spf}.`, detail,
      `Add include:${provider.spf} to the SPF record, before the all at the end.`);
  }
  if (all === "?") return result("spf", "SPF", "warn", "Ends in ?all, which tells receivers nothing.", detail);
  if (all === undefined) return result("spf", "SPF", "warn", "No all mechanism at the end.", detail);
  return result("spf", "SPF", "pass", `Valid, ${count} of ${SPF_LOOKUP_LIMIT} lookups, ends in ${all}all.`, detail);
}

export async function checkDkim(domain, resolve, extraSelectors = []) {
  const selectors = [...new Set([...extraSelectors.filter(Boolean), ...DKIM_SELECTORS])];
  const found = [];
  await Promise.all(selectors.map(async (s) => {
    const txt = (await resolve(`${s}._domainkey.${domain}`, "TXT")).join("");
    if (/(^|;)\s*p=[A-Za-z0-9+/=]{20,}/.test(txt) || /v=DKIM1/i.test(txt)) found.push(s);
  }));
  found.sort();
  if (found.length) return result("dkim", "DKIM", "pass", `Key found at selector${found.length > 1 ? "s" : ""} ${found.join(", ")}.`, found.map((s) => `${s}._domainkey.${domain}`));
  return result("dkim", "DKIM", "warn",
    `No key at ${selectors.length} common selectors. DKIM may still be set up under a custom selector; add yours to check it.`, [],
    "Turn on DKIM signing in your mail provider's admin and publish the TXT record it gives you (Google: Apps > Gmail > Authenticate email).");
}

export async function checkDmarc(domain, resolve) {
  const recs = (await resolve(`_dmarc.${domain}`, "TXT")).filter((t) => /^v=DMARC1/i.test(t));
  if (!recs.length) {
    return result("dmarc", "DMARC", "fail", "No DMARC record. Gmail and Yahoo require one from bulk senders.", [],
      `Add a TXT record at _dmarc.${domain}: v=DMARC1; p=none; rua=mailto:dmarc@${domain}`);
  }
  if (recs.length > 1) return result("dmarc", "DMARC", "fail", `${recs.length} DMARC records. Receivers ignore all of them.`, recs);
  const rec = recs[0];
  const p = ((rec.match(/(?:^|;)\s*p=([a-z]+)/i) || [])[1] || "").toLowerCase();
  const rua = /(?:^|;)\s*rua=/i.test(rec);
  const detail = [rec, rua ? "Aggregate reports are being sent (rua)." : "No rua: you get no reports on who sends as this domain."];
  if (!p) return result("dmarc", "DMARC", "fail", "DMARC record has no p= policy.", detail);
  if (p === "none") {
    return result("dmarc", "DMARC", "warn", "Policy is p=none: monitoring only. Fine to start; move to quarantine once reports look clean.", detail,
      "When the reports show only your own senders, change p=none to p=quarantine.");
  }
  return result("dmarc", "DMARC", "pass", `Policy is p=${p}.`, detail);
}

export async function checkAge(domain, rdap, now = new Date()) {
  if (!rdap) return result("age", "Domain age", "unknown", "Registration date not checked.");
  let data = null;
  try {
    data = await rdap(domain);
  } catch {
    data = null;
  }
  const reg = data?.events?.find((e) => e.eventAction === "registration")?.eventDate;
  if (!reg) return result("age", "Domain age", "unknown", "The registry didn't return a registration date.");
  const days = Math.floor((now - new Date(reg)) / 86400000);
  const when = reg.slice(0, 10);
  if (days < NEW_DOMAIN_DAYS) return result("age", "Domain age", "warn", `Registered ${days} days ago (${when}). Warm it up before sending cold email.`);
  return result("age", "Domain age", "pass", `Registered ${when}, ${days} days ago.`);
}

// Listing codes. Anything in 127.255.255.x (Spamhaus) or 127.0.0.254/1 (SURBL) means
// the query was refused, usually because it came through a public resolver.
const LISTS = [
  { zone: "dbl.spamhaus.org", name: "Spamhaus DBL", refused: (ip) => ip.startsWith("127.255.255."), listed: (ip) => ip.startsWith("127.0.1.") },
  { zone: "multi.surbl.org", name: "SURBL", refused: (ip) => ip === "127.0.0.1" || ip === "127.0.0.254", listed: (ip) => /^127\.0\.0\.\d+$/.test(ip) },
];

export async function checkBlocklists(domain, blocklist) {
  if (!blocklist) {
    return result("blocklist", "Blocklists", "unknown",
      "Not checked here: Spamhaus and SURBL refuse lookups from public DNS. Run the CLI with --system-dns from your own network.");
  }
  const detail = [];
  let listed = 0;
  let refused = 0;
  for (const l of LISTS) {
    const answers = await blocklist(`${domain}.${l.zone}`);
    if (answers === null) { refused++; detail.push(`${l.name}: couldn't query`); continue; }
    if (!answers.length) { detail.push(`${l.name}: not listed`); continue; }
    if (answers.some(l.refused)) { refused++; detail.push(`${l.name}: query refused (${answers.join(", ")})`); continue; }
    if (answers.some(l.listed)) { listed++; detail.push(`${l.name}: LISTED (${answers.join(", ")})`); continue; }
    detail.push(`${l.name}: unexpected answer ${answers.join(", ")}`);
  }
  if (listed) return result("blocklist", "Blocklists", "fail", `Listed on ${listed} blocklist${listed > 1 ? "s" : ""}. Stop sending from it.`, detail);
  if (refused === LISTS.length) return result("blocklist", "Blocklists", "unknown", "Every blocklist refused the query (public or cloud resolver).", detail);
  return result("blocklist", "Blocklists", refused ? "warn" : "pass", refused ? "Not listed where checked; some lists refused the query." : "Not listed on Spamhaus DBL or SURBL.", detail);
}

export async function checkWebsite(domain, resolve) {
  const a = await resolve(domain, "A");
  if (a.length) return result("web", "Website", "pass", "The domain resolves, so a prospect who types it in lands somewhere.");
  return result("web", "Website", "warn", "No A record. A prospect who visits the domain gets an error; point it at your main site.");
}

// A check we couldn't run doesn't make the domain look worse than the checks we did run.
const RANK = { fail: 3, warn: 2, unknown: 0, pass: 0 };

export async function checkDomain(input, { resolve, rdap = null, blocklist = null, selectors = [] }) {
  const domain = normalizeDomain(input);
  if (!domain) return { domain: String(input), status: "fail", checks: [result("input", "Domain", "fail", "That doesn't look like a domain.")] };
  const safe = async (name, type) => {
    try {
      return await resolve(name, type);
    } catch {
      return [];
    }
  };
  const { check: mx, provider } = await checkMx(domain, safe);
  const checks = [
    mx,
    ...(await Promise.all([
      checkSpf(domain, safe, provider),
      checkDkim(domain, safe, selectors),
      checkDmarc(domain, safe),
      checkBlocklists(domain, blocklist),
      checkAge(domain, rdap),
      checkWebsite(domain, safe),
    ])),
  ];
  const worst = checks.reduce((w, c) => (RANK[c.status] > RANK[w] ? c.status : w), "pass");
  return { domain, provider: provider?.name || null, status: worst, checks };
}

// ── DNS over HTTPS: works in browsers and Node 18+ ───────────────────────────
const TYPE_CODE = { A: 1, MX: 15, TXT: 16, CNAME: 5 };

export function dohResolver(endpoints = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]) {
  return async (name, type) => {
    let lastErr;
    for (const url of endpoints) {
      try {
        const r = await fetch(`${url}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: "application/dns-json" } });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j = await r.json();
        if (j.Status !== 0) return [];
        return (j.Answer || [])
          .filter((a) => a.type === TYPE_CODE[type])
          .map((a) => (type === "TXT" ? a.data.replace(/^"|"$/g, "").replace(/"\s*"/g, "") : a.data));
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr;
  };
}

// The registry's own RDAP server, found through IANA's bootstrap file. rdap.org would
// redirect there too, but it blocks requests that don't come from a browser.
let bootstrap = null;

export async function rdapLookup(domain) {
  if (!bootstrap) {
    bootstrap = fetch("https://data.iana.org/rdap/dns.json")
      .then((r) => r.json())
      .then((j) => {
        const map = {};
        for (const [tlds, servers] of j.services) for (const t of tlds) map[t] = servers[0];
        return map;
      });
  }
  const base = (await bootstrap)[domain.split(".").pop()];
  if (!base) return null;
  const r = await fetch(`${base.replace(/\/?$/, "/")}domain/${encodeURIComponent(domain)}`, { headers: { accept: "application/rdap+json" } });
  return r.ok ? r.json() : null;
}
