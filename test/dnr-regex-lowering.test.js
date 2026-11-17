import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { shimSource } from "../dist/runtime/shim.js";
import { applyDnr, dnrSafari, lowerRegexRules } from "../dist/manifest/dnr.js";
import { analyzeManifest, transformManifest } from "../dist/manifest/manifest.js";

// Chrome compiles regexFilter with RE2; Safari compiles it into a content rule list
// whose parser (WebCore URLFilterParser) takes only literals, `.`, classes, groups,
// `? * +`, a leading `^` and a trailing `$`. Live: Safari refused 249 of Bypass
// Paywalls Clean's 253 regex rules. The converter rewrites what has an exact Safari
// form and reports the rest.

const lib = dnrSafari();
// Values from the vm sandbox belong to another realm; compare plain copies.
const plain = (x) => JSON.parse(JSON.stringify(x));

// Each pattern, with URLs it must and must not match. The lowered variants, OR'd,
// must agree with the original on every one.
const CASES = [
  [String.raw`^.*\.user\.(?:css|less|styl)(?:\?.*)?$`,
    ["https://a.com/x.user.css", "https://a.com/x.user.styl?v=1"], ["https://a.com/x.user.js", "https://a.com/x.user.css#h"]],
  [String.raw`^https?://(www\.)?example\.com/\d+`,
    ["https://example.com/42", "http://www.example.com/7/x"], ["https://example.com/x", "https://wwwexample.com/1"]],
  [String.raw`/[a-f0-9]{32}\.js`,
    ["https://cdn.x/" + "ab12".repeat(8) + ".js"], ["https://cdn.x/" + "ab12".repeat(7) + ".js"]],
  [String.raw`^https://(?:[a-z0-9-]+\.)*(foo|bar)\.com/x{2,4}y`,
    ["https://foo.com/xxy", "https://a.b.bar.com/xxxxy"], ["https://foo.com/xy", "https://baz.com/xxy"]],
  [String.raw`(^|\.)ads\.example\.(com|net)/`,
    ["ads.example.com/", "https://cdn.ads.example.net/a"], ["https://badsads.example.org/", "https://xads.example.com/"]],
  [String.raw`^https?://[^/]+/\w+/(a|b|[cd])\.js$`,
    ["https://h/x_1/c.js", "http://h/abc/a.js"], ["https://h/x/e.js", "https://h/x-y/a.js"]],
  [String.raw`^https://x\.com/(\?|$)`,
    ["https://x.com/", "https://x.com/?q"], ["https://x.com/a"]],
  [String.raw`^https://s\.com/p\?id=\d{3,}`,
    ["https://s.com/p?id=123", "https://s.com/p?id=12345"], ["https://s.com/p?id=12"]],
];

for (const [pattern, yes, no] of CASES) {
  test(`lowered ${pattern} matches exactly what the original does`, () => {
    assert.ok(lib.safariRegexProblem(pattern), "precondition: Safari refuses it as written");
    const low = lib.lowerRegex(pattern, false);
    assert.equal(low.error, undefined, low.error);
    for (const v of low.variants) assert.equal(lib.safariRegexProblem(v.source), null, `variant ${v.source} must be Safari-clean`);
    const orig = new RegExp(pattern, "i");
    const any = (u) => low.variants.some((v) => new RegExp(v.source, "i").test(u));
    for (const u of yes) { assert.ok(orig.test(u), `fixture: ${u}`); assert.ok(any(u), `should match ${u}`); }
    for (const u of no) { assert.ok(!orig.test(u), `fixture: ${u}`); assert.ok(!any(u), `should not match ${u}`); }
  });
}

test("Safari-clean patterns are left exactly as written", () => {
  for (const p of [String.raw`^https://example\.com/.*`, String.raw`[?&]utm_[a-z]+=`, String.raw`^https?://([^/]*\.)?ads\.com/`]) {
    assert.equal(lib.safariRegexProblem(p), null, p);
    const res = lib.lowerRule({ id: 1, condition: { regexFilter: p }, action: { type: "block" } }, () => 99);
    assert.equal(res.changed, false);
  }
});

test("constructs with no Safari form are reported, not mangled", () => {
  const refused = [
    ["foo(?=bar)", /lookaround/],
    ["(?<!a)b", /lookaround/],
    [String.raw`\bads\b`, /word boundary/],
    [String.raw`(a)\1`, /backreference/],
    ["(ab|cd)+x", /repeated alternation/],
    [".*", /matches every URL/],
    ["a{100}", /repetition larger/],
  ];
  for (const [p, why] of refused) {
    const low = lib.lowerRegex(p, false);
    assert.match(low.error ?? "", why, p);
  }
});

test("POSIX classes inside brackets become explicit ranges", () => {
  const low = lib.lowerRegex(String.raw`^https://a\.com/[\d_]+[[:alpha:]]?\.png`, false);
  assert.deepEqual(plain(low.variants.map((v) => v.source)), ["^https://a\\.com/[0-9_]+[A-Za-z]?\\.png"]);
});

test("a leading (?i) becomes the rule's case-insensitive flag", () => {
  const res = lib.lowerRule({ id: 1, condition: { regexFilter: "(?i)^https://SHOP\\.example/", isUrlFilterCaseSensitive: true }, action: { type: "block" } }, () => 99);
  assert.equal(res.rules[0].condition.regexFilter, "^https://SHOP\\.example/");
  assert.equal(res.rules[0].condition.isUrlFilterCaseSensitive, false);
});

test("regexSubstitution group numbers follow each split branch", () => {
  let n = 100;
  const res = lib.lowerRule({
    id: 1,
    condition: { regexFilter: String.raw`^https://(a|bb)\.com/(?:xx|y)/(\d+)` },
    action: { type: "redirect", redirect: { regexSubstitution: "https://z.com/\\2?h=\\1&u=\\0" } },
  }, () => n++);
  assert.equal(res.rules.length, 4);
  for (const r of res.rules) {
    const m = new RegExp(r.condition.regexFilter).exec("https://bb.com/y/42") ?? new RegExp(r.condition.regexFilter).exec("https://a.com/xx/42");
    if (!m) continue;
    const out = r.action.redirect.regexSubstitution.replace(/\\(\d)/g, (_, d) => m[+d] ?? "");
    assert.match(out, /^https:\/\/z\.com\/42\?h=(a|bb)&u=https:\/\/(a|bb)\.com\/(xx|y)\/42$/, `${r.condition.regexFilter} -> ${out}`);
  }
  assert.deepEqual(res.rules.map((r) => r.id), [1, 100, 101, 102]);
});

test("static ruleset: lowered in place, extra ids above the ruleset's largest, the rest reported", () => {
  const dir = mkdtempSync(join(tmpdir(), "viaduct-dnr-rx-"));
  const rules = [
    { id: 5, action: { type: "block" }, condition: { regexFilter: String.raw`^https://(ad|tr)\.ads\.com/\d+` } },
    { id: 9, action: { type: "block" }, condition: { regexFilter: String.raw`^https://x\.com/(?=y)` } },
    { id: 2, action: { type: "block" }, condition: { urlFilter: "||tracker.example" } },
  ];
  writeFileSync(join(dir, "rules.json"), JSON.stringify(rules), "utf-8");
  const notes = applyDnr(dir, { declarative_net_request: { rule_resources: [{ id: "rs", path: "rules.json" }] } });
  const out = JSON.parse(readFileSync(join(dir, "rules.json"), "utf-8"));
  assert.deepEqual(out.map((r) => r.id), [5, 10, 9, 2]);
  assert.deepEqual(out.slice(0, 2).map((r) => r.condition.regexFilter), ["^https://ad\\.ads\\.com/[0-9]+", "^https://tr\\.ads\\.com/[0-9]+"]);
  assert.equal(out[2].condition.regexFilter, rules[1].condition.regexFilter, "unlowerable rule left as written");
  assert.ok(notes.some((n) => /rewrote 1 regexFilter/.test(n) && /ids from 10/.test(n)), JSON.stringify(notes));
  assert.ok(notes.some((n) => /1 regexFilter rule\(s\) use regex Safari can't express/.test(n) && /rule ids: 9/.test(n)), JSON.stringify(notes));
  const again = lowerRegexRules(out);
  assert.equal(again.lowered, 0, "running it twice changes nothing");
});

// ── runtime: dynamic rules ──
function storageArea() {
  const data = {};
  return {
    data,
    get(key, cb) { const o = {}; if (key in data) o[key] = data[key]; cb?.(o); return Promise.resolve(o); },
    set(obj, cb) { Object.assign(data, JSON.parse(JSON.stringify(obj))); cb?.(); return Promise.resolve(); },
  };
}
function boot({ nativeRegexCheck = true } = {}) {
  const store = new Map();
  const dnr = {
    updateDynamicRules(opts) {
      for (const id of opts?.removeRuleIds ?? []) store.delete(id);
      for (const r of opts?.addRules ?? []) {
        if (r.condition?.regexFilter && lib.safariRegexProblem(r.condition.regexFilter)) {
          throw new Error(`Invalid call. The 'addRules' value is invalid, because an error with rule at index 0: Rule with id ${r.id} is invalid. \`regexFilter\` is not a supported regular expression.`);
        }
      }
      for (const r of opts?.addRules ?? []) store.set(r.id, r);
      return Promise.resolve();
    },
    getDynamicRules(filter) {
      let rules = [...store.values()];
      if (filter?.ruleIds) rules = rules.filter((r) => filter.ruleIds.includes(r.id));
      return Promise.resolve(JSON.parse(JSON.stringify(rules)));
    },
  };
  if (nativeRegexCheck) {
    dnr.isRegexSupported = (o) => Promise.resolve(lib.safariRegexProblem(o.regex) ? { isSupported: false, reason: "syntaxError" } : { isSupported: true });
  }
  // Shim timers must not keep the test process alive.
  const unref = (fn) => (...args) => { const h = fn(...args); h?.unref?.(); return h; };
  const sandbox = {
    console, setTimeout: unref(setTimeout), clearTimeout, setInterval: unref(setInterval), clearInterval, URL,
    location: { href: "safari-web-extension://TEST/background.html", pathname: "/background.html", protocol: "safari-web-extension:" },
    navigator: { userAgent: "test" },
    chrome: {
      runtime: { id: "t", getURL: (p) => "safari-web-extension://TEST/" + p, onMessage: { addListener() {}, removeListener() {} }, sendMessage() {} },
      storage: { local: storageArea(), session: storageArea(), onChanged: { addListener() {} } },
      declarativeNetRequest: dnr,
    },
  };
  sandbox.window = sandbox; sandbox.self = sandbox; sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(shimSource(), sandbox);
  return { dnr: sandbox.chrome.declarativeNetRequest, store, sandbox };
}

const SPLIT = { id: 3, priority: 1, action: { type: "block" }, condition: { regexFilter: String.raw`^https://(ads|track)\.example/\d+`, resourceTypes: ["script"] } };

test("a dynamic rule is split for Safari, and get/remove still see the extension's one rule", async () => {
  const { dnr, store } = boot();
  await dnr.updateDynamicRules({ addRules: [SPLIT, { id: 4, action: { type: "block" }, condition: { urlFilter: "||x.example" } }] });
  assert.equal(store.size, 3, "Safari holds both branches plus the plain rule");
  const listed = await dnr.getDynamicRules();
  assert.deepEqual(plain(listed.map((r) => r.id).sort()), [3, 4]);
  assert.equal(listed.find((r) => r.id === 3).condition.regexFilter, SPLIT.condition.regexFilter, "handed back as registered");
  await dnr.updateDynamicRules({ removeRuleIds: [3] });
  assert.deepEqual([...store.keys()], [4], "removing the original id removes its split-off rule too");
});

test("callback form of getDynamicRules gets the same view", async () => {
  const { dnr } = boot();
  await dnr.updateDynamicRules({ addRules: [SPLIT] });
  const rules = await new Promise((resolve) => dnr.getDynamicRules(resolve));
  assert.deepEqual(plain(rules.map((r) => r.id)), [3]);
});

test("isRegexSupported says yes for a pattern the shim can lower, no for one it can't", async () => {
  for (const nativeRegexCheck of [true, false]) {
    const { dnr } = boot({ nativeRegexCheck });
    assert.deepEqual(plain(await dnr.isRegexSupported({ regex: String.raw`^https://(a|b)\.com/\d+` })), { isSupported: true });
    assert.equal((await dnr.isRegexSupported({ regex: "(?<=a)b" })).isSupported, false);
  }
});

// ── manifest: the permission WebKit gates header and redirect actions on ──
test("both DNR tokens are declared, whichever one the extension used", () => {
  const cases = [
    [{ manifest_version: 3, permissions: ["declarativeNetRequest"] }, "permissions"],
    [{ manifest_version: 3, permissions: ["declarativeNetRequestWithHostAccess"] }, "permissions"],
    [{ manifest_version: 3, optional_permissions: ["declarativeNetRequestWithHostAccess"] }, "optional_permissions"],
  ];
  for (const [m, key] of cases) {
    const { permissionsToRemove } = analyzeManifest(m);
    assert.ok(!permissionsToRemove.includes("declarativeNetRequestWithHostAccess"), "no longer stripped");
    const out = transformManifest(m, permissionsToRemove, mkdtempSync(join(tmpdir(), "viaduct-m-")), { keepModuleBackground: false });
    for (const t of ["declarativeNetRequest", "declarativeNetRequestWithHostAccess"]) assert.ok(out[key].includes(t), `${key} has ${t}`);
  }
  const none = transformManifest({ manifest_version: 3, permissions: ["tabs"] }, [], mkdtempSync(join(tmpdir(), "viaduct-m-")), { keepModuleBackground: false });
  assert.deepEqual(none.permissions, ["tabs"], "not added to an extension without DNR");
});
