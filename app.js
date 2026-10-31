import { checkDomain, dohResolver, normalizeDomain, rdapLookup } from "./core.js";

const MAX_DOMAINS = 50;
const PARALLEL = 4;
const LABEL = { pass: "Pass", warn: "Warning", fail: "Fail", unknown: "Not checked" };

const $ = (id) => document.getElementById(id);
const form = $("form");
const resultsEl = $("results");
const resolve = dohResolver();
let lastResults = [];

function parseDomains(text) {
  const seen = new Set();
  const out = [];
  for (const raw of text.split(/[\s,;]+/)) {
    const d = normalizeDomain(raw);
    if (d && !seen.has(d)) {
      seen.add(d);
      out.push(d);
    }
  }
  return out.slice(0, MAX_DOMAINS);
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null) node.append(c.nodeType ? c : document.createTextNode(c));
  return node;
}

function copyButton(text) {
  const b = el("button", { type: "button", class: "copy" }, "Copy");
  b.addEventListener("click", async () => {
    await navigator.clipboard.writeText(text);
    b.textContent = "Copied";
    setTimeout(() => (b.textContent = "Copy"), 1500);
  });
  return b;
}

function fixRecord(fix) {
  // "Add a TXT record at X: VALUE" -> show the value on its own line with a copy button
  const m = fix.match(/^Add a TXT record at ([^:]+): (.+)$/);
  if (!m) return el("p", { class: "fix" }, fix);
  return el("div", { class: "fix" },
    el("p", {}, "Add a TXT record at ", el("code", {}, m[1])),
    el("div", { class: "record" }, el("code", {}, m[2]), copyButton(m[2])));
}

function renderCard(r) {
  const rows = r.checks.map((c) => {
    const open = c.status === "fail" || c.status === "warn";
    const body = [];
    if (c.fix && c.status !== "pass") body.push(fixRecord(c.fix));
    if (c.detail?.length) body.push(el("ul", { class: "detail" }, c.detail.map((d) => el("li", {}, el("code", {}, d)))));
    return el("details", { class: `check ${c.status}`, ...(open ? { open: "" } : {}) },
      el("summary", {},
        el("span", { class: `pill ${c.status}` }, LABEL[c.status]),
        el("span", { class: "label" }, c.label),
        el("span", { class: "text" }, c.summary)),
      body.length ? el("div", { class: "body" }, body) : null);
  });
  return el("article", { class: `card ${r.status}` },
    el("div", { class: "card-head" },
      el("h3", {}, r.domain),
      r.provider ? el("span", { class: "provider" }, r.provider) : null,
      el("span", { class: `pill big ${r.status}` }, LABEL[r.status])),
    rows);
}

function renderPending(domain) {
  return el("article", { class: "card pending", "data-domain": domain },
    el("div", { class: "card-head" }, el("h3", {}, domain), el("span", { class: "spinner", "aria-label": "checking" })));
}

function renderCounts(results) {
  const n = (s) => results.filter((r) => r.status === s).length;
  $("counts").replaceChildren(
    el("span", {}, el("b", {}, String(results.length)), " checked"),
    el("span", { class: "fail" }, el("b", {}, String(n("fail"))), " failing"),
    el("span", { class: "warn" }, el("b", {}, String(n("warn"))), " with warnings"),
    el("span", { class: "pass" }, el("b", {}, String(n("pass"))), " healthy"));
}

async function run(domains, selector) {
  resultsEl.replaceChildren(...domains.map(renderPending));
  $("summary").hidden = true;
  $("go").disabled = true;
  lastResults = new Array(domains.length);
  let next = 0;
  async function worker() {
    while (next < domains.length) {
      const i = next++;
      const r = await checkDomain(domains[i], { resolve, rdap: rdapLookup, selectors: selector ? [selector] : [] });
      lastResults[i] = r;
      resultsEl.children[i].replaceWith(renderCard(r));
    }
  }
  await Promise.all(Array.from({ length: PARALLEL }, worker));
  $("go").disabled = false;
  renderCounts(lastResults);
  $("summary").hidden = false;
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const domains = parseDomains($("domains").value);
  if (!domains.length) {
    resultsEl.replaceChildren(el("p", { class: "empty" }, "Add at least one domain, like acme.com."));
    return;
  }
  const selector = $("selector").value.trim();
  const url = new URL(location.href);
  url.searchParams.set("d", domains.join(","));
  if (selector) url.searchParams.set("s", selector);
  else url.searchParams.delete("s");
  history.replaceState(null, "", url);
  run(domains, selector);
});

$("copy-link").addEventListener("click", async (e) => {
  await navigator.clipboard.writeText(location.href);
  e.target.textContent = "Link copied";
  setTimeout(() => (e.target.textContent = "Copy share link"), 1500);
});

$("csv").addEventListener("click", () => {
  const cols = ["domain", "provider", "overall", "mx", "spf", "dkim", "dmarc", "age", "web", "blocklist", "problems"];
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines = [cols.join(",")];
  for (const r of lastResults.filter(Boolean)) {
    const by = Object.fromEntries(r.checks.map((c) => [c.id, c.status]));
    const problems = r.checks.filter((c) => c.status === "fail" || c.status === "warn").map((c) => `${c.label}: ${c.summary}`).join(" | ");
    lines.push([r.domain, r.provider, r.status, by.mx, by.spf, by.dkim, by.dmarc, by.age, by.web, by.blocklist, problems].map(q).join(","));
  }
  const a = el("a", { href: URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" })), download: "domain-health.csv" });
  a.click();
});

const params = new URLSearchParams(location.search);
if (params.get("d")) {
  $("domains").value = params.get("d").split(",").join("\n");
  $("selector").value = params.get("s") || "";
  form.requestSubmit();
}
