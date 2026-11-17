import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { shimSource } from "../dist/runtime/shim.js";
import { applyDnr, sanitizeModifyHeaders } from "../dist/manifest/dnr.js";

// Safari validates every header operation of a modifyHeaders rule and THROWS out of
// update{Session,Dynamic}Rules on the first one it refuses, costing the extension
// every other rule in the batch. What it refuses (WebKit's
// _validateHeaderInfoDictionary + WebCore HTTPParsers):
//   - shipping releases: a name off WebCore's known-header list (x-forwarded-for,
//     any custom x-*); WebKit main takes any HTTP token
//   - set/append on a request header the network stack owns (Host, Proxy-*, ...)
//   - append on a request header with no defined delimiter
// The shim drops just those operations and keeps the rest of the rule, which Safari
// applies once the extension holds declarativeNetRequestWithHostAccess.

const KNOWN = new Set(["user-agent", "referer", "cookie", "authorization", "accept-language"]);
function boot({ strictNames = true, throwOnFirstBatch = false } = {}) {
  const applied = [];
  const removed = [];
  const sandbox = {
    console,
    setTimeout, clearTimeout, setInterval, clearInterval,
    location: { href: "safari-web-extension://TEST/background.html" },
    navigator: { userAgent: "test" },
    applied,
    removed,
    chrome: {
      runtime: {
        id: "test-ext",
        getURL: (p) => "safari-web-extension://TEST/" + p,
        onMessage: { addListener() {}, removeListener() {} },
        sendMessage() {},
      },
      declarativeNetRequest: {
        updateSessionRules(opts) {
          const rules = opts?.addRules ?? [];
          // Stand-in for WebKit's validator: it THROWS (does not reject).
          rules.forEach((r, i) => {
            for (const h of r?.action?.requestHeaders ?? []) {
              if (strictNames && !KNOWN.has(h.header.toLowerCase())) {
                throw new Error(
                  "Invalid call to declarativeNetRequest.updateSessionRules(). The 'addRules' value is invalid, because an error " +
                    `with rule at index ${i}: Rule with id ${r.id} is invalid. The header \`${h.header}\` is not recognized.`
                );
              }
            }
          });
          if (throwOnFirstBatch && rules.length > 1) {
            throw new Error("Invalid call to declarativeNetRequest.updateSessionRules().");
          }
          for (const id of opts?.removeRuleIds ?? []) removed.push(id);
          for (const r of rules) applied.push(r);
          return Promise.resolve();
        },
      },
    },
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(shimSource(), sandbox);
  return sandbox;
}

const headerRule = (id) => ({
  id,
  priority: 1,
  action: {
    type: "modifyHeaders",
    requestHeaders: [
      { header: "user-agent", operation: "set", value: "Googlebot/2.1" },
      { header: "x-forwarded-for", operation: "set", value: "185.1.2.3" },
    ],
  },
  condition: { urlFilter: "||example.com", resourceTypes: ["main_frame"] },
});
const blockRule = (id) => ({
  id,
  priority: 1,
  action: { type: "block" },
  condition: { urlFilter: "||ads.example", resourceTypes: ["script"] },
});
// Values from the vm sandbox belong to another realm; compare plain copies.
const plain = (x) => JSON.parse(JSON.stringify(x));
const ops = (r) => plain(r.action.requestHeaders.map((h) => h.header));

test("a header Safari doesn't know is dropped from the rule; the rule and its batch-mates land", async () => {
  const s = boot({ strictNames: true });
  await s.chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [7],
    addRules: [headerRule(1), blockRule(2)],
  });
  assert.deepEqual(s.applied.map((r) => r.id), [1, 2], "both rules must land");
  assert.deepEqual(ops(s.applied[0]), ["user-agent"], "only the refused operation goes");
  assert.deepEqual(s.removed, [7], "removals must still be applied");
});

test("on a Safari that takes any header token, custom headers are kept", async () => {
  const s = boot({ strictNames: false });
  await s.chrome.declarativeNetRequest.updateSessionRules({ addRules: [headerRule(1)] });
  assert.deepEqual(ops(s.applied[0]), ["user-agent", "x-forwarded-for"]);
});

test("request headers Safari won't touch are dropped up front, and an emptied rule goes", async () => {
  const s = boot({ strictNames: false });
  await s.chrome.declarativeNetRequest.updateSessionRules({
    addRules: [
      { id: 1, action: { type: "modifyHeaders", requestHeaders: [
        { header: "Host", operation: "set", value: "evil.example" },
        { header: "referer", operation: "append", value: "x" },
        { header: "cookie", operation: "append", value: "a=1" },
        { header: "accept-language", operation: "remove", value: "" },
      ] }, condition: { urlFilter: "*" } },
      { id: 2, action: { type: "modifyHeaders", requestHeaders: [{ header: "proxy-authorization", operation: "set", value: "x" }] }, condition: { urlFilter: "*" } },
      blockRule(3),
    ],
  });
  assert.deepEqual(s.applied.map((r) => r.id), [1, 3]);
  assert.deepEqual(plain(s.applied[0].action.requestHeaders), [
    { header: "cookie", operation: "append", value: "a=1" },
    { header: "accept-language", operation: "remove" },
  ], "Host can't be set, referer can't be appended to, and a remove carries no value");
});

test("the caller's rule array is not mutated", async () => {
  const s = boot();
  const rules = [headerRule(1), blockRule(2)];
  await s.chrome.declarativeNetRequest.updateSessionRules({ addRules: rules });
  assert.equal(rules.length, 2);
  assert.equal(rules[0].action.requestHeaders.length, 2);
});

test("a synchronous throw from Safari is salvaged, not propagated to the extension", async () => {
  // Safari reports a rule it dislikes by throwing OUT of the call rather than through
  // the callback. Unhandled, that aborts the extension's registration code mid-way, so
  // the wrapper catches it and re-tries the batch one rule at a time.
  const s = boot({ throwOnFirstBatch: true });
  await new Promise((resolve) => {
    s.chrome.declarativeNetRequest.updateSessionRules({ addRules: [blockRule(1), blockRule(2)] }, resolve);
  });
  assert.deepEqual(s.applied.map((r) => r.id), [1, 2], "both rules land through the salvage");
});

test("sanitizeModifyHeaders keeps other action types by identity and validates strictly", () => {
  const block = blockRule(1);
  const res = sanitizeModifyHeaders([block, headerRule(2)]);
  assert.equal(res.rules[0], block);
  assert.deepEqual(ops(res.rules[1]), ["user-agent"]);
  assert.equal(res.droppedRules, 0);
  assert.deepEqual(res.droppedOps.map((d) => [d.id, d.header]), [[2, "x-forwarded-for"]]);
});

test("applyDnr keeps a static header rule, minus the operations Safari refuses", () => {
  const dir = mkdtempSync(join(tmpdir(), "viaduct-dnr-"));
  writeFileSync(join(dir, "rules.json"), JSON.stringify([blockRule(1), headerRule(2)]), "utf-8");
  const notes = applyDnr(dir, {
    host_permissions: ["*://*.example.com/*"],
    declarative_net_request: { rule_resources: [{ id: "ruleset", path: "rules.json", enabled: true }] },
  });
  const written = JSON.parse(readFileSync(join(dir, "rules.json"), "utf-8"));
  assert.deepEqual(written.map((r) => r.id), [1, 2]);
  assert.deepEqual(ops(written[1]), ["user-agent"]);
  assert.ok(notes.some((n) => /removed 1 header operation/.test(n) && /x-forwarded-for/.test(n)), JSON.stringify(notes));
  assert.ok(notes.some((n) => /only on websites the user has granted/.test(n)), JSON.stringify(notes));
});

test("applyDnr warns when header/redirect rules have no host permission to act on", () => {
  const dir = mkdtempSync(join(tmpdir(), "viaduct-dnr-"));
  writeFileSync(join(dir, "rules.json"), JSON.stringify([headerRule(1)]), "utf-8");
  const notes = applyDnr(dir, { declarative_net_request: { rule_resources: [{ id: "r", path: "rules.json" }] } });
  assert.ok(notes.some((n) => /declares no host permissions/.test(n)), JSON.stringify(notes));
});
