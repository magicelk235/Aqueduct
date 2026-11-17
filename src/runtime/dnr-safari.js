// Safari-specific declarativeNetRequest rule fixes, shared by the build-time
// transform (src/manifest/dnr.ts, static rulesets) and the runtime shim
// (dynamic/session rules). Plain ES5 with no imports: shimSource() splices this
// file over the `// __C2S_DNR_SAFARI__` marker, and dnr.ts evaluates it with
// `new Function`. Keep it self-contained.
//
// Everything here mirrors WebKit's validators, read from source:
//   - header ops:  _WKWebExtensionDeclarativeNetRequestRule.mm
//                  (_validateHeaderInfoDictionary) + WebCore HTTPParsers.cpp
//                  (isRequestHeaderUnsafeToModify, requestHeaderAppendDelimiter)
//   - regexFilter: WebCore contentextensions/URLFilterParser.cpp, which is what
//                  `[WKContentRuleList _supportsRegularExpression:]` runs.
var c2sDnrSafari = (function () {
  "use strict";

  // ── modifyHeaders ─────────────────────────────────────────────────────────
  // Shipping Safari only accepts header names WebCore knows (HTTPHeaderNames.in);
  // anything else ("x-forwarded-for", "anthropic-client-version") makes the whole
  // update call throw "The header `…` is not recognized." WebKit main relaxed this
  // to any valid HTTP token. `strict` picks the shipping behavior.
  var KNOWN_HEADERS = ("accept accept-charset accept-language accept-encoding accept-ranges " +
    "access-control-allow-credentials access-control-allow-headers access-control-allow-methods " +
    "access-control-allow-origin access-control-expose-headers access-control-max-age " +
    "access-control-request-headers access-control-request-method age authorization " +
    "available-dictionary cache-control clear-site-data connection content-disposition " +
    "content-encoding content-language content-length content-location content-security-policy " +
    "content-security-policy-report-only content-type content-range cookie cookie2 " +
    "cross-origin-embedder-policy cross-origin-embedder-policy-report-only cross-origin-opener-policy " +
    "cross-origin-opener-policy-report-only cross-origin-resource-policy date dictionary-id dnt " +
    "default-style document-isolation-policy document-isolation-policy-report-only etag expect " +
    "expires host if-match if-modified-since if-none-match if-range if-unmodified-since " +
    "integrity-policy integrity-policy-report-only keep-alive last-event-id last-modified link " +
    "location origin origin-agent-cluster ping-from ping-to pragma proxy-authorization range " +
    "referer referrer-policy refresh report-to reporting-endpoints sec-fetch-dest sec-fetch-mode " +
    "sec-fetch-site sec-gpc sec-purpose sec-speculation-tags speculation-rules sec-websocket-accept " +
    "sec-websocket-extensions sec-websocket-key sec-websocket-protocol sec-websocket-version " +
    "server-timing service-worker service-worker-allowed service-worker-navigation-preload " +
    "set-cookie set-cookie2 sourcemap te timing-allow-origin trailer transfer-encoding upgrade " +
    "upgrade-insecure-requests use-as-dictionary user-agent vary via x-content-type-options " +
    "x-frame-options x-sourcemap x-xss-protection x-temp-tablet icy-metaint icy-metadata").split(" ");
  var APPENDABLE = ("accept accept-encoding accept-language access-control-request-headers " +
    "cache-control connection content-language cookie forwarded if-match if-none-match keep-alive " +
    "range te trailer transfer-encoding upgrade user-agent via want-digest x-forwarded-for").split(" ");
  var UNSAFE = ("available-dictionary content-length cookie2 host keep-alive set-cookie te trailer " +
    "transfer-encoding upgrade").split(" ");
  function setOf(list) { var o = Object.create(null); for (var i = 0; i < list.length; i++) o[list[i]] = 1; return o; }
  var KNOWN_SET = setOf(KNOWN_HEADERS), APPEND_SET = setOf(APPENDABLE), UNSAFE_SET = setOf(UNSAFE);
  var TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

  function splitTrim(v) { return String(v).split(",").map(function (s) { return s.replace(/^\s+|\s+$/g, ""); }); }
  function requestHeaderUnsafe(name, value) {
    if (UNSAFE_SET[name] || name.indexOf("proxy-") === 0) return true;
    if (name === "accept-encoding") {
      return splitTrim(value).some(function (e) { e = e.split(";")[0].replace(/\s+$/, "").toLowerCase(); return e === "dcb" || e === "dcz" || e === "*"; });
    }
    if (name === "connection") {
      return splitTrim(value).some(function (t) { t = t.toLowerCase(); return t && t !== "close" && t !== "keep-alive"; });
    }
    if (name === "x-http-method-override" || name === "x-http-method" || name === "x-method-override") {
      return splitTrim(value).some(function (m) { m = m.toUpperCase(); return m === "CONNECT" || m === "TRACE" || m === "TRACK"; });
    }
    return false;
  }

  // Why Safari would refuse this one header operation, or null if it takes it.
  function headerOpProblem(op, isRequest, strict) {
    if (!op || typeof op !== "object") return "malformed header entry";
    var name = op.header, kind = op.operation, value = op.value;
    if (typeof name !== "string" || !TOKEN.test(name)) return "invalid header name";
    var n = name.toLowerCase();
    if (strict && !KNOWN_SET[n]) return "`" + name + "` is not a header name Safari recognizes";
    if (kind !== "set" && kind !== "append" && kind !== "remove") return "unknown operation `" + kind + "`";
    if (kind !== "remove" && typeof value !== "string") return "missing value";
    if (typeof value === "string" && /[\0\r\n]/.test(value)) return "value contains NUL/CR/LF";
    if (isRequest && kind !== "remove" && requestHeaderUnsafe(n, value)) return "Safari refuses to modify request header `" + name + "`";
    if (isRequest && kind === "append" && !APPEND_SET[n]) return "Safari can't append to request header `" + name + "`";
    return null;
  }

  // Keep the header operations Safari accepts and drop only the rest, instead of
  // the whole rule. Returns { rule, dropped: [{ header, why }] }; `rule` is the
  // input object itself when nothing changed, a copy when something did, and null
  // when no operation survives (Safari rejects a modifyHeaders rule with an empty
  // or absent header list).
  function sanitizeHeaderRule(rule, strict) {
    var a = rule && rule.action;
    if (!a || a.type !== "modifyHeaders") return { rule: rule, dropped: [] };
    var dropped = [], changed = false, out = {};
    ["requestHeaders", "responseHeaders"].forEach(function (key) {
      if (a[key] == null) return;
      if (!Array.isArray(a[key])) { changed = true; dropped.push({ header: key, why: "not an array" }); return; }
      var kept = [];
      a[key].forEach(function (op) {
        var fixed = op;
        // A value on a remove is refused outright; it carries no meaning, drop it.
        if (op && op.operation === "remove" && op.value != null) {
          fixed = Object.assign({}, op); delete fixed.value; changed = true;
        }
        var why = headerOpProblem(fixed, key === "requestHeaders", strict);
        if (why) { changed = true; dropped.push({ header: String(op && op.header), why: why }); }
        else kept.push(fixed);
      });
      if (kept.length) out[key] = kept;
      else changed = true; // emptied (or empty to begin with): Safari refuses []
    });
    if (!out.requestHeaders && !out.responseHeaders) return { rule: null, dropped: dropped };
    if (!changed) return { rule: rule, dropped: dropped };
    var na = Object.assign({}, a);
    delete na.requestHeaders; delete na.responseHeaders;
    if (out.requestHeaders) na.requestHeaders = out.requestHeaders;
    if (out.responseHeaders) na.responseHeaders = out.responseHeaders;
    return { rule: Object.assign({}, rule, { action: na }), dropped: dropped };
  }

  // ── regexFilter ───────────────────────────────────────────────────────────
  // Chrome compiles regexFilter with RE2; Safari compiles it into a content rule
  // list, which takes only: literals, `.`, `[...]` classes, groups, `?` `*` `+`,
  // `^` as the first token and `$` as the last. Everything else is refused, and
  // a pattern every term of which can match empty is refused as "matches
  // everything". The lowering below rewrites what can be rewritten exactly:
  //   \d \w \s (and inside classes, and POSIX [:alpha:]) -> explicit classes
  //   {n} {n,m} {n,}                                     -> unrolled copies
  //   (a|b|[cd])                                         -> [abcd]
  //   other alternation                                  -> one pattern per branch
  //   leading (?i)                                       -> case-insensitive flag
  // and reports the rest (lookaround, backreference, \b, repeated alternation).
  var MAX_VARIANTS = 32, MAX_REPEAT = 64, MAX_LENGTH = 4096;
  function ascii(from, to) { var s = new Array(128); for (var i = 0; i < 128; i++) s[i] = i >= from && i <= to; return s; }
  function union(a, b) { var s = new Array(128); for (var i = 0; i < 128; i++) s[i] = !!(a[i] || b[i]); return s; }
  function invert(a) { var s = new Array(128); for (var i = 0; i < 128; i++) s[i] = !a[i]; return s; }
  function chars(str) { var s = ascii(1, 0); for (var i = 0; i < str.length; i++) s[str.charCodeAt(i)] = true; return s; }
  var DIGIT = ascii(48, 57);
  var UPPER = ascii(65, 90), LOWER = ascii(97, 122);
  var ALPHA = union(UPPER, LOWER), ALNUM = union(ALPHA, DIGIT);
  var WORD = union(ALNUM, chars("_"));
  var SPACE = chars(" \t\n\r\f\v");
  var XDIGIT = union(DIGIT, union(ascii(65, 70), ascii(97, 102)));
  var PUNCT = (function () { var s = ascii(33, 126); for (var i = 0; i < 128; i++) if (ALNUM[i]) s[i] = false; return s; })();
  var POSIX = { alpha: ALPHA, digit: DIGIT, alnum: ALNUM, upper: UPPER, lower: LOWER, space: SPACE, xdigit: XDIGIT, word: WORD, punct: PUNCT,
    blank: chars(" \t"), cntrl: union(ascii(0, 31), ascii(127, 127)), print: ascii(32, 126), graph: ascii(33, 126) };
  var BUILTIN = { d: DIGIT, w: WORD, s: SPACE };
  var SIMPLE_ESC = { t: 9, n: 10, r: 13, f: 12, v: 11 };

  function Fail(why) { this.why = why; }

  // Parse into { alt: [[term]] }. term = { atom, min, max, lazy }.
  // atom kinds: set (one character: literal, `.`, class, \d …), group, bol, eol.
  // Each set atom notes whether it was written in a form Safari refuses
  // (`builtin`), so the same parse also answers "does Safari take it as is?".
  function parse(src) {
    var i = 0, groupCount = 0, caseInsensitive = false;
    if (src.indexOf("(?i)") === 0) { caseInsensitive = true; i = 4; }
    function peek() { return src.charAt(i); }
    function hex(n) {
      var h = src.substr(i, n);
      if (h.length !== n || !/^[0-9a-fA-F]+$/.test(h)) return -1;
      i += n; return parseInt(h, 16);
    }
    function codeAtom(c) {
      if (c > 127) throw new Fail("non-ASCII character");
      var s = ascii(1, 0); s[c] = true;
      return { k: "set", set: s, lit: c };
    }
    // An escape outside or inside a class, `\` already consumed.
    function escape(inClass) {
      var c = src.charAt(i++);
      if (c === "") throw new Fail("trailing backslash");
      var lo = c.toLowerCase();
      if (BUILTIN[lo]) return { set: c === lo ? BUILTIN[lo] : invert(BUILTIN[lo]), builtin: true, negated: c !== lo };
      if (SIMPLE_ESC[c] != null) return { code: SIMPLE_ESC[c] };
      if (c === "x") { var x = hex(2); if (x < 0) return { code: 120 }; return { code: x }; }
      if (c === "u") { var u = hex(4); if (u < 0) return { code: 117 }; return { code: u }; }
      if (c === "c" && /[A-Za-z]/.test(peek())) { return { code: src.charCodeAt(i++) % 32 }; }
      if (c === "0" && !/[0-9]/.test(peek())) return { code: 0 };
      if (inClass && c === "b") return { code: 8 };
      if (inClass && c === "-") return { code: 45 };
      if (!inClass) {
        if (c === "b" || c === "B") throw new Fail("word boundary (\\b) has no Safari equivalent");
        if (/[1-9]/.test(c)) throw new Fail("backreference");
        if (c === "k") throw new Fail("backreference");
        if (c === "A") return { bol: true };
        if (c === "z" || c === "Z") return { eol: true };
      }
      if (c === "p" || c === "P") throw new Fail("Unicode property class");
      if (c === "Q") throw new Fail("\\Q…\\E quoting");
      if (/[A-Za-z0-9]/.test(c)) throw new Fail("unknown escape \\" + c);
      return { code: c.charCodeAt(0) };
    }
    function klass() {
      // `[` consumed.
      var neg = false, set = ascii(1, 0), builtin = false, first = true;
      if (peek() === "^") { neg = true; i++; }
      if (peek() === "]") throw new Fail("class starting with `]`");
      for (;;) {
        if (i >= src.length) throw new Fail("unterminated character class");
        var c = src.charAt(i);
        if (c === "]") { i++; break; }
        var lowCode = -1;
        if (c === "[" && src.charAt(i + 1) === ":") {
          var end = src.indexOf(":]", i + 2);
          var nm = end > 0 ? src.slice(i + 2, end) : "";
          var pn = nm.charAt(0) === "^" ? nm.slice(1) : nm;
          if (!POSIX[pn]) throw new Fail("unknown POSIX class [:" + nm + ":]");
          set = union(set, nm.charAt(0) === "^" ? invert(POSIX[pn]) : POSIX[pn]);
          builtin = true; i = end + 2; first = false; continue;
        }
        i++;
        if (c === "\\") {
          var e = escape(true);
          if (e.set) { set = union(set, e.set); builtin = true; first = false; continue; }
          lowCode = e.code;
        } else {
          lowCode = c.charCodeAt(0);
        }
        // Range?
        if (peek() === "-" && src.charAt(i + 1) !== "]" && i + 1 < src.length) {
          i++;
          var hc = src.charAt(i++), highCode;
          if (hc === "\\") {
            var he = escape(true);
            if (he.set) throw new Fail("class range ending in a class escape");
            highCode = he.code;
          } else highCode = hc.charCodeAt(0);
          if (highCode < lowCode) throw new Fail("reversed class range");
          if (lowCode > 127) throw new Fail("non-ASCII character");
          set = union(set, ascii(lowCode, Math.min(highCode, 127)));
          if (highCode > 127) builtin = true; // the non-ASCII tail can't match a URL
        } else {
          if (lowCode > 127) throw new Fail("non-ASCII character");
          set[lowCode] = true;
        }
        first = false;
      }
      void first;
      // Safari keeps `[^…]` as written; expressing it positively only matters
      // when it is merged or rewritten, which works on the ASCII set.
      return { k: "set", set: neg ? invert(set) : set, neg: neg, raw: set, builtin: builtin, cls: true };
    }
    function quant(term) {
      var c = peek();
      if (c === "*") { term.min = 0; term.max = Infinity; i++; }
      else if (c === "+") { term.min = 1; term.max = Infinity; i++; }
      else if (c === "?") { term.min = 0; term.max = 1; i++; }
      else if (c === "{") {
        var m = /^\{(\d+)(,(\d*))?\}/.exec(src.slice(i));
        if (!m) return; // a literal `{`, as in JS and RE2
        term.min = +m[1];
        term.max = m[2] ? (m[3] === "" ? Infinity : +m[3]) : term.min;
        if (term.max < term.min) throw new Fail("quantifier {n,m} with m < n");
        term.braces = true;
        i += m[0].length;
      } else return;
      if (peek() === "?") { term.lazy = true; i++; }
      if (/[*+?{]/.test(peek()) && !(peek() === "{" && !/^\{\d+(,\d*)?\}/.test(src.slice(i)))) throw new Fail("stacked quantifiers");
    }
    function alternation(depth) {
      var alt = [[]];
      for (;;) {
        if (i >= src.length) { if (depth) throw new Fail("unterminated group"); return alt; }
        var c = src.charAt(i);
        if (c === ")") { if (!depth) throw new Fail("unbalanced `)`"); i++; return alt; }
        if (c === "|") { i++; alt.push([]); continue; }
        var atom;
        i++;
        if (c === "(") {
          var cap = true, named = false;
          if (peek() === "?") {
            var rest = src.slice(i, i + 4);
            if (rest.indexOf("?:") === 0) { cap = false; i += 2; }
            else if (/^\?P?<[A-Za-z_]/.test(rest)) {
              var close = src.indexOf(">", i);
              if (close < 0) throw new Fail("unterminated group name");
              named = rest.charAt(1) === "P"; i = close + 1;
            }
            else if (/^\?<?[=!]/.test(rest)) throw new Fail("lookaround has no Safari equivalent");
            else throw new Fail("inline flag group");
          }
          var idx = cap ? ++groupCount : 0;
          atom = { k: "group", cap: cap, idx: idx, named: named, alt: alternation(depth + 1) };
        } else if (c === "[") atom = klass();
        else if (c === ".") atom = { k: "set", set: invert(chars("\n\r")), dot: true };
        else if (c === "^") atom = { k: "bol" };
        else if (c === "$") atom = { k: "eol" };
        else if (c === "\\") {
          var e = escape(false);
          if (e.bol) atom = { k: "bol", builtin: true };
          else if (e.eol) atom = { k: "eol", builtin: true };
          else if (e.set) atom = { k: "set", set: e.set, builtin: true, neg: !!e.negated };
          else atom = codeAtom(e.code);
        } else if (c === "*" || c === "+" || c === "?") throw new Fail("quantifier with nothing to repeat");
        else atom = codeAtom(c.charCodeAt(0));
        var term = { atom: atom, min: 1, max: 1, lazy: false };
        quant(term);
        alt[alt.length - 1].push(term);
      }
    }
    var tree = alternation(0);
    return { alt: tree, groupCount: groupCount, caseInsensitive: caseInsensitive };
  }

  function nullableAtom(a) {
    if (a.k === "bol" || a.k === "eol") return true;
    if (a.k === "set") return false;
    return a.alt.some(function (seq) { return seq.every(function (t) { return t.min === 0 || nullableAtom(t.atom); }); });
  }

  // Does Safari take this pattern exactly as written? null = yes, else why not.
  function safariRegexProblem(src) {
    if (typeof src !== "string" || !src.length) return "empty pattern";
    if (/[^\x00-\x7f]/.test(src)) return "non-ASCII character";
    if (src.indexOf("(?i)") === 0) return "inline (?i) flag";
    var p;
    try { p = parse(src); } catch (e) { if (e instanceof Fail) return e.why; throw e; }
    var why = null;
    function walk(alt, top) {
      if (alt.length > 1) { why = why || "alternation (|)"; return; }
      var seq = alt[0];
      seq.forEach(function (t, n) {
        var a = t.atom;
        if (why) return;
        if (a.builtin) { why = a.k === "set" ? "\\d, \\w, \\s or POSIX class" : "\\A or \\z anchor"; return; }
        if (a.k === "group" && a.named) { why = "named group"; return; }
        var q = t.min + "," + t.max;
        if (q !== "1,1" && q !== "0,1" && q !== "0,Infinity" && q !== "1,Infinity") { why = "{n,m} repetition"; return; }
        if (a.k === "bol" && (!top || n !== 0 || q !== "1,1")) { why = "`^` not at the start"; return; }
        if (a.k === "eol" && (!top || n !== seq.length - 1 || q !== "1,1")) { why = "`$` not at the end"; return; }
        if (a.k === "group") walk(a.alt, false);
      });
    }
    walk(p.alt, true);
    if (why) return why;
    var top = p.alt[0];
    if (top.every(function (t) { return t.min === 0 || nullableAtom(t.atom); })) return "matches every URL";
    return null;
  }

  // ── emission ──
  function escLit(c) {
    var ch = String.fromCharCode(c);
    if ("\\^$.|?*+()[]{}".indexOf(ch) >= 0) return "\\" + ch;
    if (c < 32 || c === 127) return "\\x" + (c < 16 ? "0" : "") + c.toString(16);
    return ch;
  }
  function escClass(c) {
    var ch = String.fromCharCode(c);
    if ("\\]^-[".indexOf(ch) >= 0) return "\\" + ch;
    if (c < 32 || c === 127) return "\\x" + (c < 16 ? "0" : "") + c.toString(16);
    return ch;
  }
  function count(set) { var n = 0; for (var i = 0; i < 128; i++) if (set[i]) n++; return n; }
  function ranges(set) {
    var out = "", i = 0;
    while (i < 128) {
      if (!set[i]) { i++; continue; }
      var j = i; while (j + 1 < 128 && set[j + 1]) j++;
      if (j === i) out += escClass(i);
      else if (j === i + 1) out += escClass(i) + escClass(j);
      else out += escClass(i) + "-" + escClass(j);
      i = j + 1;
    }
    return out;
  }
  // One character position. A class written as `[^…]` stays negated so it keeps
  // matching what it matched (Safari's own [^…] covers non-ASCII too).
  function emitSet(a) {
    if (a.lit != null) return escLit(a.lit);
    if (a.dot) return ".";
    var set = a.set;
    var n = count(set);
    if (n === 128) return ".";
    if (n === 0) throw new Fail("character class that matches nothing");
    if (n === 1) for (var c = 0; c < 128; c++) if (set[c]) return escLit(c);
    // Keep the polarity the author wrote: `[^…]`, \D, \W, \S stay negated (and so
    // keep matching non-ASCII, as they did); everything else is spelled positively.
    if (a.neg) return "[^" + ranges(invert(set)) + "]";
    return "[" + ranges(set) + "]";
  }

  // A variant is a token list. Tokens:
  //   { k: "one", set, s }   one unquantified character position (mergeable)
  //   { k: "s", s }          anything else already rendered
  //   { k: "bol" } { k: "eol" }
  //   { k: "cap", idx }      an emitted capturing `(` for original group idx
  function cross(a, b) {
    var out = [];
    for (var i = 0; i < a.length; i++) for (var j = 0; j < b.length; j++) {
      out.push(a[i].concat(b[j]));
      if (out.length > MAX_VARIANTS) throw new Fail("expands to more than " + MAX_VARIANTS + " patterns");
    }
    return out;
  }
  function qs(min, max) {
    if (min === 1 && max === 1) return "";
    if (min === 0 && max === 1) return "?";
    if (min === 0) return "*";
    return "+";
  }
  function render(tokens) {
    return tokens.map(function (t) { return t.k === "bol" ? "^" : t.k === "eol" ? "$" : t.k === "cap" ? "(" : t.s; }).join("");
  }
  function hasAnchor(tokens) { return tokens.some(function (t) { return t.k === "bol" || t.k === "eol"; }); }

  function lowerAlt(alt, keepCaps) {
    var out = [];
    alt.forEach(function (seq) { lowerSeq(seq, keepCaps).forEach(function (v) { out.push(v); }); });
    if (out.length > MAX_VARIANTS) throw new Fail("expands to more than " + MAX_VARIANTS + " patterns");
    return out;
  }
  function lowerSeq(seq, keepCaps) {
    var vs = [[]];
    seq.forEach(function (t) { vs = cross(vs, lowerTerm(t, keepCaps)); });
    return vs;
  }
  // One quantified atom, at most `?`/`*`/`+`: the term's variants.
  function lowerOnce(a, q, keepCaps, capHere) {
    if (a.k === "bol" || a.k === "eol") {
      if (q) throw new Fail("quantified anchor");
      return [[{ k: a.k }]];
    }
    if (a.k === "set") {
      var s = emitSet(a);
      return [[q ? { k: "s", s: s + q } : { k: "one", set: a.set, s: s }]];
    }
    // group
    var inner = lowerAlt(a.alt, keepCaps);
    var cap = capHere && keepCaps && a.cap;
    // Every branch one character (or empty): merge into a single class.
    var single = inner.every(function (v) { return v.length === 0 || (v.length === 1 && v[0].k === "one"); });
    if (inner.length > 1 && single) {
      var set = ascii(1, 0), hasEmpty = false;
      inner.forEach(function (v) { if (!v.length) hasEmpty = true; else set = union(set, v[0].set); });
      // Every branch empty: the group matches only the empty string.
      if (!count(set)) return [cap ? [{ k: "cap", idx: a.idx }, { k: "s", s: ")" }] : []];
      var cs = emitSet({ set: set });
      var mq = q;
      if (hasEmpty) mq = q === "" || q === "?" ? "?" : "*";
      if (cap) return [[{ k: "cap", idx: a.idx }, { k: "s", s: cs + ")" + mq }]];
      return [[mq ? { k: "s", s: cs + mq } : { k: "one", set: set, s: cs }]];
    }
    function wrap(v, quant) {
      if (cap) return [{ k: "cap", idx: a.idx }].concat(v, [{ k: "s", s: ")" + quant }]);
      if (!quant) return v; // flatten: no parens needed
      if (hasAnchor(v)) throw new Fail("anchor inside a repeated group");
      var open = keepCaps ? "(?:" : "(";
      return [{ k: "s", s: open }].concat(v, [{ k: "s", s: ")" + quant }]);
    }
    if (inner.length === 1 && !cap && inner[0].length === 1 && inner[0][0].k === "one") {
      var one = inner[0][0];
      return [[q ? { k: "s", s: one.s + q } : one]];
    }
    if (inner.length === 1) return [wrap(inner[0], q)];
    if (q === "") return inner.map(function (v) { return wrap(v, ""); });
    if (q === "?") return [[]].concat(inner.map(function (v) { return wrap(v, ""); }));
    throw new Fail("repeated alternation ((a|bc)+)");
  }
  function lowerTerm(t, keepCaps) {
    var a = t.atom, min = t.min, max = t.max;
    // Laziness only changes which match is reported, never whether one exists;
    // it does change capture contents, so keep it exact when captures matter.
    if (t.lazy && keepCaps && min !== max) throw new Fail("lazy quantifier in a regexSubstitution rule");
    var q = qs(min, max);
    var direct = (min === 1 && max === 1) || (min === 0 && max === 1) || (min === 0 && max === Infinity) || (min === 1 && max === Infinity);
    if (direct) return lowerOnce(a, q, keepCaps, true);
    // {n}, {n,m}, {n,}: unroll into copies Safari can take.
    if (min > MAX_REPEAT || (max !== Infinity && max > MAX_REPEAT)) throw new Fail("repetition larger than {" + MAX_REPEAT + "}");
    if (a.k === "group" && a.cap && keepCaps && max !== min) throw new Fail("variable repetition of a captured group in a regexSubstitution rule");
    var copies = [];
    var mandatory = max === Infinity ? min - 1 : min;
    for (var n = 0; n < mandatory; n++) copies.push("");
    if (max === Infinity) copies.push("+");
    else for (var o = 0; o < max - min; o++) copies.push("?");
    var vs = [[]];
    copies.forEach(function (cq, n) {
      // Only the last copy captures, matching JS/RE2's "last iteration" rule.
      vs = cross(vs, lowerOnce(a, cq, keepCaps, n === copies.length - 1));
    });
    return vs;
  }

  // Lower one pattern. keepCaps: the rule's redirect uses regexSubstitution, so
  // capture numbers must be tracked. Returns { variants: [{ source, groupMap }],
  // caseInsensitive } or throws Fail. groupMap[orig] = new group number (absent
  // = that group doesn't take part in this variant).
  function lowerRegex(src, keepCaps) {
    if (/[^\x00-\x7f]/.test(src)) throw new Fail("non-ASCII character");
    var p = parse(src);
    var vs = lowerAlt(p.alt, keepCaps);
    var seen = Object.create(null), out = [];
    vs.forEach(function (tokens) {
      var source = render(tokens);
      if (seen[source]) return;
      seen[source] = 1;
      if (source.length > MAX_LENGTH) throw new Fail("lowered pattern longer than " + MAX_LENGTH + " characters");
      // Only `cap` tokens open capturing groups when captures matter; repeated
      // non-captured groups are emitted as `(?:`, and plain `(` only appears when
      // captures don't matter.
      var groupMap = {}, g = 0;
      tokens.forEach(function (t) { if (t.k === "cap") groupMap[t.idx] = ++g; });
      var why = safariRegexProblem(source);
      if (why) throw new Fail(why);
      out.push({ source: source, groupMap: groupMap });
    });
    return { variants: out, caseInsensitive: p.caseInsensitive };
  }

  // Can Safari take this pattern, as is or once lowered? For isRegexSupported.
  function regexSupportable(src) {
    if (!safariRegexProblem(src)) return true;
    try { lowerRegex(src, false); return true; } catch (e) { if (e instanceof Fail) return false; throw e; }
  }

  function remapSubstitution(sub, groupMap) {
    return sub.replace(/\\(\\|\d)/g, function (m, d) {
      if (d === "\\" || d === "0") return m;
      return groupMap[+d] ? "\\" + groupMap[+d] : "";
    });
  }

  // Rewrite one rule so Safari takes its regexFilter. `nextId()` hands out ids
  // for the extra rules alternation splits into. Returns
  //   { rules: [rule], changed: false }                  untouched
  //   { rules: [rule, …], changed: true, split: n }      lowered
  //   { rules: [rule], changed: false, error: why }      Safari will refuse it
  function lowerRule(rule, nextId) {
    var c = rule && rule.condition;
    if (!c || typeof c.regexFilter !== "string") return { rules: [rule], changed: false };
    var problem = safariRegexProblem(c.regexFilter);
    if (!problem) return { rules: [rule], changed: false };
    var a = rule.action || {};
    var sub = a.type === "redirect" && a.redirect && typeof a.redirect.regexSubstitution === "string" ? a.redirect.regexSubstitution : null;
    var low;
    try { low = lowerRegex(c.regexFilter, sub != null); }
    catch (e) { if (e instanceof Fail) return { rules: [rule], changed: false, error: e.why }; throw e; }
    var rules = low.variants.map(function (v, n) {
      var nc = Object.assign({}, c, { regexFilter: v.source });
      if (low.caseInsensitive) nc.isUrlFilterCaseSensitive = false;
      var r = Object.assign({}, rule, { condition: nc });
      if (n > 0) r.id = nextId();
      if (sub != null) {
        r.action = Object.assign({}, a, { redirect: Object.assign({}, a.redirect, { regexSubstitution: remapSubstitution(sub, v.groupMap) }) });
      }
      return r;
    });
    return { rules: rules, changed: true, split: rules.length, was: problem };
  }

  return {
    sanitizeHeaderRule: sanitizeHeaderRule,
    headerOpProblem: headerOpProblem,
    safariRegexProblem: safariRegexProblem,
    regexSupportable: regexSupportable,
    lowerRule: lowerRule,
    lowerRegex: function (src, keepCaps) {
      try { return lowerRegex(src, !!keepCaps); } catch (e) { if (e instanceof Fail) return { error: e.why }; throw e; }
    },
  };
})();
