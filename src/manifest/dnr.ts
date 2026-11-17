import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, relative, isAbsolute, join } from "node:path";
import type { Manifest } from "../types.js";
import { parseJsonc } from "./manifest.js";
import { RUNTIME_DIR } from "../paths.js";

// res.path comes from the extension's manifest.json — untrusted. A path like
// "../../etc/x" would make join() resolve outside stageDir, and the rule rewrite
// below writeFileSync()s back to it: arbitrary file overwrite from a malicious
// extension. Confirm the resolved path stays under stageDir.
// String-prefix check via path.relative; fine for a local single root.
function resolveInside(stageDir: string, p: string): string | null {
  const full = resolve(stageDir, p);
  const rel = relative(resolve(stageDir), full);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return null;
  return full;
}

/** True if the extension talks to api.anthropic.com (CSP, host_permissions, etc.). */
export function needsAnthropicCorsBypass(manifest: Manifest): boolean {
  return /api\.anthropic\.com/i.test(JSON.stringify(manifest));
}

interface DnrRule {
  id?: number;
  action?: { type?: string; redirect?: { regexSubstitution?: string } };
  condition?: { regexFilter?: unknown };
}

interface LowerResult {
  rules: DnrRule[];
  changed: boolean;
  split?: number;
  error?: string;
}

/** The rule fixes shared with the runtime shim (src/runtime/dnr-safari.js). */
export interface DnrSafari {
  sanitizeHeaderRule(rule: unknown, strict: boolean): { rule: DnrRule | null; dropped: { header: string; why: string }[] };
  safariRegexProblem(src: string): string | null;
  regexSupportable(src: string): boolean;
  lowerRule(rule: unknown, nextId: () => number): LowerResult;
  lowerRegex(src: string, keepCaps?: boolean): { variants?: { source: string; groupMap: Record<number, number> }[]; caseInsensitive?: boolean; error?: string };
}

let dnrSafariCache: DnrSafari | null = null;
/**
 * Load the shared rule fixes. They live in one plain-JS file so the shim (which
 * splices the file in) and this build step run the exact same validator.
 */
export function dnrSafari(): DnrSafari {
  if (!dnrSafariCache) {
    const src = readFileSync(join(RUNTIME_DIR, "dnr-safari.js"), "utf-8");
    dnrSafariCache = new Function(`${src}\nreturn c2sDnrSafari;`)() as DnrSafari;
  }
  return dnrSafariCache;
}

// WebKit caps enabled static DNR rules per extension at 30,000 (same as Chrome's
// guaranteed minimum); rules past the cap are silently dropped at load. Warn (not
// strip) past this threshold so the author can split/trim rather than ship a
// half-applied ruleset.
const SAFARI_STATIC_RULE_GUIDELINE = 30000;

/**
 * Keep the header operations Safari accepts, drop only the ones it refuses.
 *
 * Safari validates each header operation and refuses the WHOLE rule (in a static
 * ruleset) or the whole update call (dynamic/session, a synchronous throw) for one
 * bad entry. What it refuses, from WebKit's validator:
 *   - a header name outside WebCore's known-header list on shipping releases
 *     (`x-forwarded-for`, any custom `x-*`); WebKit main accepts any HTTP token,
 *     but static rules can't tell which Safari will load them, so be strict here;
 *   - set/append on request headers the network stack owns (Host, Content-Length,
 *     Proxy-*, Transfer-Encoding, …);
 *   - append on a request header without a defined delimiter.
 * A rule left with no operation is dropped (Safari rejects an empty header list).
 *
 * Earlier releases of this converter dropped every modifyHeaders rule, because
 * Safari accepted them and never applied them. That was the missing
 * declarativeNetRequestWithHostAccess permission (see transformManifest), not
 * the action itself.
 */
export function sanitizeModifyHeaders(rules: unknown[], strict = true): {
  rules: unknown[];
  droppedRules: number;
  droppedOps: { id: unknown; header: string; why: string }[];
} {
  const lib = dnrSafari();
  const out: unknown[] = [];
  const droppedOps: { id: unknown; header: string; why: string }[] = [];
  let droppedRules = 0;
  for (const r of rules as DnrRule[]) {
    const res = lib.sanitizeHeaderRule(r, strict);
    for (const d of res.dropped) droppedOps.push({ id: r?.id, ...d });
    if (res.rule) out.push(res.rule);
    else droppedRules++;
  }
  return { rules: out, droppedRules, droppedOps };
}

/**
 * Rewrite regexFilter rules Safari's content-rule-list compiler refuses into
 * patterns it takes (see dnr-safari.js for the rewrites), splitting alternation
 * into one rule per branch. Extra rules get ids above the ruleset's largest.
 */
export function lowerRegexRules(rules: unknown[]): {
  rules: unknown[];
  lowered: number;
  added: number;
  firstAddedId: number;
  unsupported: { id: unknown; why: string }[];
} {
  const lib = dnrSafari();
  let maxId = 0;
  for (const r of rules as DnrRule[]) if (typeof r?.id === "number" && r.id > maxId) maxId = r.id;
  const firstAddedId = maxId + 1;
  const nextId = () => ++maxId;
  const out: unknown[] = [];
  const unsupported: { id: unknown; why: string }[] = [];
  let lowered = 0, added = 0;
  for (const r of rules as DnrRule[]) {
    const res = lib.lowerRule(r, nextId);
    if (res.error) unsupported.push({ id: r?.id, why: res.error });
    if (res.changed) { lowered++; added += res.rules.length - 1; }
    out.push(...res.rules);
  }
  return { rules: out, lowered, added, firstAddedId, unsupported };
}

function summarize(items: { why: string }[], max = 4): string {
  const counts = new Map<string, number>();
  for (const i of items) counts.set(i.why, (counts.get(i.why) ?? 0) + 1);
  const parts = [...counts].sort((a, b) => b[1] - a[1]).slice(0, max).map(([why, n]) => `${why} (${n})`);
  if (counts.size > max) parts.push(`${counts.size - max} more`);
  return parts.join("; ");
}

function idList(ids: unknown[], max = 10): string {
  const shown = ids.slice(0, max).map(String).join(", ");
  return ids.length > max ? `${shown}, … (${ids.length} total)` : shown;
}

/**
 * Sanitize declarativeNetRequest static rulesets for Safari and report changes.
 *
 * - modifyHeaders: per-operation validation (sanitizeModifyHeaders).
 * - regexFilter: lowered into Safari's regex subset (lowerRegexRules); what can't
 *   be lowered stays and is reported by rule id, since Safari will refuse it.
 * Static rule_resources load straight from disk and never reach the runtime shim,
 * which applies the same fixes to dynamic and session rules.
 *
 * api.anthropic.com's org CORS gate keys on `sec-fetch-site`, a browser-controlled
 * forbidden header that JS cannot set and that Safari refuses to let DNR modify;
 * the only viable path is an out-of-process native-messaging proxy, so no
 * CORS-bypass ruleset is shipped — just a note.
 */
export function applyDnr(stageDir: string, manifest: Manifest): string[] {
  const notes: string[] = [];
  let enabledRuleCount = 0;
  let hostScopedRules = 0;

  for (const res of manifest.declarative_net_request?.rule_resources ?? []) {
    if (!res || typeof res.path !== "string") {
      notes.push("DNR rule_resources entry is missing a valid 'path'; Safari will fail to load it.");
      continue;
    }
    const id = res.id ?? res.path;
    const file = resolveInside(stageDir, res.path);
    if (file === null) {
      notes.push(`DNR ruleset "${id}" path ${res.path} escapes the extension directory; skipped.`);
      continue;
    }
    if (!existsSync(file)) {
      notes.push(`DNR ruleset "${id}" points to missing file ${res.path}; Safari will fail to load it.`);
      continue;
    }
    let rules: unknown;
    try {
      // Same lenient parse as the manifest: Chrome tolerates BOM/comments/trailing
      // commas in rule files, and a parse failure here would SKIP the fixes below
      // while Safari still loads the raw file.
      rules = parseJsonc(readFileSync(file, "utf-8"));
    } catch {
      notes.push(`DNR ruleset "${id}" (${res.path}) is not valid JSON; Safari will fail to load it.`);
      continue;
    }
    if (!Array.isArray(rules)) {
      notes.push(`DNR ruleset "${id}" (${res.path}) is not a JSON array of rules; Safari will fail to load it.`);
      continue;
    }

    const hdr = sanitizeModifyHeaders(rules);
    const rx = lowerRegexRules(hdr.rules);
    const safe = rx.rules as DnrRule[];
    if (hdr.droppedOps.length || hdr.droppedRules || rx.lowered) {
      writeFileSync(file, JSON.stringify(safe, null, 2) + "\n", "utf-8");
    }
    if (hdr.droppedOps.length) {
      notes.push(
        `DNR ruleset "${id}": removed ${hdr.droppedOps.length} header operation(s) Safari refuses ` +
          `[${summarize(hdr.droppedOps)}]` +
          (hdr.droppedRules ? `; ${hdr.droppedRules} modifyHeaders rule(s) had nothing left and were dropped` : "") +
          ". The rest of each rule is kept."
      );
    }
    if (rx.lowered) {
      notes.push(
        `DNR ruleset "${id}": rewrote ${rx.lowered} regexFilter rule(s) into Safari's regex subset` +
          (rx.added
            ? ` (alternation split them into ${rx.added} extra rule(s) with ids from ${rx.firstAddedId}; ` +
              "updateStaticRules({disableRuleIds}) on an original id does not reach those)"
            : "") +
          "."
      );
    }
    if (rx.unsupported.length) {
      notes.push(
        `DNR ruleset "${id}": ${rx.unsupported.length} regexFilter rule(s) use regex Safari can't express and will be ignored ` +
          `[${summarize(rx.unsupported)}]; rule ids: ${idList(rx.unsupported.map((u) => u.id))}. Rewrite them with urlFilter or a simpler regex.`
      );
    }

    if (res.enabled !== false) {
      enabledRuleCount += safe.length;
      hostScopedRules += safe.filter((r) => r?.action?.type === "modifyHeaders" || r?.action?.type === "redirect").length;
    }
  }

  if (enabledRuleCount > SAFARI_STATIC_RULE_GUIDELINE) {
    notes.push(
      `Enabled static DNR rules (${enabledRuleCount}) exceed the ~${SAFARI_STATIC_RULE_GUIDELINE} Safari honors; ` +
        "rules past the cap load in Chrome but are silently ignored in Safari. Trim or split the rulesets."
    );
  }

  // Safari applies redirect and modifyHeaders only on hosts the extension holds
  // (granted) host permissions for; Chrome's declarativeNetRequest permission
  // needs none. Without any host pattern those rules do nothing.
  if (hostScopedRules) {
    const hostPatterns = [
      ...(Array.isArray(manifest.host_permissions) ? manifest.host_permissions : []),
      ...(Array.isArray(manifest.optional_host_permissions) ? manifest.optional_host_permissions : []),
      ...(Array.isArray(manifest.permissions) ? manifest.permissions : []).filter((p) => typeof p === "string" && (p === "<all_urls>" || p.includes("://"))),
    ];
    notes.push(
      hostPatterns.length
        ? `${hostScopedRules} static redirect/modifyHeaders rule(s): Safari applies these only on websites the user has granted the extension access to, and only from the next page load after granting.`
        : `${hostScopedRules} static redirect/modifyHeaders rule(s), but the extension declares no host permissions: Safari applies these actions only on granted hosts, so they will do nothing. Add host_permissions covering the rules' targets.`
    );
  }

  if (needsAnthropicCorsBypass(manifest)) {
    const allPerms = [
      ...(Array.isArray(manifest.permissions) ? manifest.permissions : []),
      ...(Array.isArray(manifest.optional_permissions) ? manifest.optional_permissions : []),
    ];
    const nmNote = allPerms.includes("nativeMessaging")
      ? "Requires the nativeMessaging permission (present here)."
      : "Requires the nativeMessaging permission (NOT declared here; add it or the retry cannot reach the native host).";
    notes.push(
      "api.anthropic.com calls hit an org CORS gate that cannot be bypassed in-browser " +
        "(the gate keys on sec-fetch-site, which Safari's DNR refuses to modify). The shim now retries blocked backend " +
        "requests through the native host (SafariWebExtensionHandler), which sets the Chrome " +
        `Origin server-side. ${nmNote}`
    );
  }
  return notes;
}
