// The one masking routine for everything mcpsafe prints: config excerpts (-v
// and the HTML report), command lines, finding messages and evidence, and the
// error messages of --connect.
//
// A value is hidden when the MCS001 detection (findSecrets) reports it, given
// the key, --flag or header name it belongs to (arguments and command lines
// are read with argValues() and splitCommandLine(), the same parsers MCS001
// uses, so whatever it reports is hidden), and also when it has one of a
// few structural forms: a password in a URL, a credential query parameter, a
// Bearer or Basic value, or a value whose key names a credential. Masking is
// told about secrets found elsewhere in the same config (`known`), so a
// secret repeated without context is hidden as well.
//
// Every scan here is linear in the length of the text: the regular
// expressions are anchored or bounded, and known secrets are looked up by a
// fixed-length prefix rather than tried one by one.
import { argValues, findSecrets, isPlaceholder, keyLooksSecret, looksLikeEnvName, looksLikeSetting, mask, SECRET_PATTERNS } from './secrets.js';
import { splitCommandLineSpans } from './packages.js';

export const BULLETS = '••••••••';

// A URL query parameter whose name says it holds a credential. The name is
// matched as a whole word (after splitting camelCase), so "design",
// "keyboard" or "author" do not count.
const CRED_PARAM = /^(?:.*[_.-])?(?:api[_-]?key|apikey|key|token|secret|password|passwd|pwd|auth|sig|signature|credentials?|access[_-]?(?:token|key)|client[_-]?secret)$/i;
export const isCredentialParam = (k) => CRED_PARAM.test(String(k).replace(/([a-z0-9])([A-Z])/g, '$1_$2'));

// Known token formats, the same ones MCS001 looks for. The 'd' flag gives
// the position of the group that holds the secret (a database password).
const PATTERNS = SECRET_PATTERNS.map((p) => ({
  name: p.name,
  valid: p.valid,
  group: p.group || 0,
  re: new RegExp(p.re.source, `${p.re.flags.replace(/[gd]/g, '')}gd`),
}));

// These add to what argValues() (the MCS001 parser) finds; they never take
// away from it. Keys may start with any word character and have any length.
const FLAG = /^--?([\w.-]+)$/; // --token, -k, --2fa-secret
const HEADER_NAME = /(?:^|[=:])([A-Za-z][\w-]*):$/; // "x-api-key:" or "--header=x-api-key:"
const HEADER_WORD = /^[A-Za-z][\w-]*$/; // "x-api-key" in "x-api-key : value"
const AUTH = /(?:^|[=:])(Bearer|Basic|Token)$/i; // "Bearer", "Authorization:Bearer"
const KV = /^-{0,2}([\w.-]+)([=:])/; // --api-key=v, API_KEY=v, X-Api-Key:v
const AUTH_VALUE = /^[A-Za-z0-9._~+/=-]{16,}$/;
const LEAD = new Set(['"', "'", '`', '(', '[', '{', '<']);
const TRAIL = new Set(['"', "'", '`', ')', ']', '}', '>', ',', ';', '.']);
const OPENER = { ')': '(', ']': '[', '}': '{', '>': '<' };
const QUERY = /[?&]([\w.-]{1,64})=([^&#\s"'<>\\]*)/g;
const WORD = /\S+/g;

// findSecrets() results for the secretRanges() call that is running, so a
// value judged by more than one rule (or repeated in the text) is judged once.
let cache = null;
function detect(v, key) {
  if (!cache) return findSecrets(v, key);
  const id = `${key}\0${v}`;
  let r = cache.get(id);
  if (!r) { r = findSecrets(v, key); cache.set(id, r); }
  return r;
}

// A value that a credential-named key holds and that is worth hiding even
// when it is not random enough for MCS001 (a short or simple password).
function plausible(v, key) {
  return v.length >= 6 && !/\s/.test(v) && !v.startsWith('-') && !v.includes('••••') && !/^(Bearer|Basic|Token)$/i.test(v)
    && !looksLikeEnvName(v) && !isPlaceholder(v) && !looksLikeSetting(v, key);
}

// Every occurrence of `secret` within s[a, b).
function occurrences(s, a, b, secret, ranges) {
  if (!secret) return;
  for (let i = s.indexOf(secret, a); i >= 0 && i + secret.length <= b; i = s.indexOf(secret, i + secret.length)) {
    ranges.push([i, i + secret.length, false]);
  }
}

// s[a, b) is the value of `key`: hide what MCS001 reports in it, or all of it
// when the key names a credential.
function judge(s, a, b, key, ranges) {
  if (b - a < 6) return;
  const v = s.slice(a, b);
  // Known formats are found by patterns() wherever they are. What needs the
  // key is a Bearer value and a random value under a credential name. No
  // finding is possible in fewer than 12 characters.
  const found = new Set();
  if (v.length >= 12) {
    for (const d of detect(v, key)) if (d.confidence !== 'high' || d.type === 'Authorization header credential') found.add(d.secret);
  }
  if (found.size > 4) knownRanges(s, secretIndex(found, 1), ranges, a, b);
  else for (const x of found) occurrences(s, a, b, x, ranges);
  if (!found.size && key && (keyLooksSecret(key) || isCredentialParam(key)) && plausible(v, key)) ranges.push([a, b, false]);
}

// --api-key=v, API_KEY="v", X-Api-Key:v, and one level of nesting such as
// --header=X-Api-Key:v.
function judgeKV(s, a, b, ranges, depth = 0) {
  const m = KV.exec(s.slice(a, b));
  if (!m) return;
  let va = a + m[0].length;
  let vb = b;
  if (va >= vb) return;
  if (m[2] === ':' && (s[va] === '/' || s[va] === '\\')) return; // https://..., C:\...
  if ((s[va] === '"' || s[va] === "'")) { if (s[vb - 1] === s[va] && vb - 1 > va) vb--; va++; }
  judge(s, va, vb, m[1], ranges);
  if (depth < 2) judgeKV(s, va, vb, ranges, depth + 1);
}

// What the word before a value says about it: a --flag or header name gives
// its key, Bearer/Basic/Token says it is an Authorization value.
function contextOf(word, before = '') {
  if (!word) return null;
  const w = word.replace(/["']/g, '');
  let m;
  if ((m = FLAG.exec(w))) return { key: m[1] };
  if ((m = AUTH.exec(w))) return { auth: m[1].toLowerCase() };
  if ((m = HEADER_NAME.exec(w))) return { key: m[1] };
  // "X-Api-Key : value": a colon on its own after a header name.
  if (w === ':' && (m = HEADER_WORD.exec(before.replace(/["']/g, '')))) return { key: m[0] };
  return null;
}

function lastWord(s) {
  const t = String(s ?? '').trimEnd();
  const i = Math.max(t.lastIndexOf(' '), t.lastIndexOf('\t'), t.lastIndexOf('\n'));
  return t.slice(i + 1);
}

// Words separated by white space, with quotes and brackets around them
// removed, each judged with the context of the word before it.
function words(s, ctx, ranges) {
  let before = '';
  for (const m of s.matchAll(WORD)) {
    let a = m.index;
    let b = a + m[0].length;
    while (a < b && LEAD.has(s[a])) a++;
    // A closing bracket stays when the word opens it too, as in ${VAR} or (x).
    const word = s.slice(a, b);
    const opens = new Set(['(', '[', '{', '<'].filter((o) => word.includes(o)));
    while (b > a && TRAIL.has(s[b - 1]) && !opens.has(OPENER[s[b - 1]])) b--;
    if (a < b && ctx) {
      if (ctx.key) judge(s, a, b, ctx.key, ranges);
      else if (ctx.auth) {
        const v = s.slice(a, b);
        if ((ctx.auth !== 'token' && AUTH_VALUE.test(v) && !isPlaceholder(v)) || (v.length >= 12 && detect(v, 'bearer').length)) ranges.push([a, b, false]);
      }
    }
    if (a < b) judgeKV(s, a, b, ranges);
    const text = s.slice(a, b) || m[0];
    ctx = contextOf(text, before);
    before = text;
  }
}

// s[a, b) is a value, or holds it written with quotes or escapes: hide every
// place where one of `secrets` is in it, or all of it when none is there as
// written (a value with ${...} references or shell quoting). Many secrets
// are looked up by prefix, so this stays linear.
function hideIn(s, a, b, secrets, ranges) {
  const n = ranges.length;
  if (secrets.size > 4) knownRanges(s, secretIndex(secrets, 1), ranges, a, b);
  else for (const x of secrets) occurrences(s, a, b, x, ranges);
  if (ranges.length === n) ranges.push([a, b, false]);
}

// What MCS001 reports in one argument, read with argValues(), the parser that
// detection uses. `arg` is all of s when `span` is not given; otherwise it is
// the unquoted text of the word s[span.start, span.end). No finding is
// possible in fewer than 12 characters.
function argRanges(s, arg, prev, ranges, span) {
  if (arg.length < 12) return;
  for (const { key, value, offset } of argValues(arg, prev)) {
    if (value.length < 12) continue;
    const dets = detect(value, key);
    if (!dets.length) continue;
    const found = new Set(dets.map((d) => d.secret).filter(Boolean));
    if (span) hideIn(s, span.start, span.end, found, ranges);
    else hideIn(s, offset, offset + value.length, found, ranges);
  }
}

// The text as one argument (with `prev` before it) and, when it has white
// space, as a command line split the way MCS001 splits a `command` string.
function args(s, prev, ranges) {
  argRanges(s, s, prev, ranges, null);
  if (!/\s/.test(s)) return;
  let last = '';
  for (const w of splitCommandLineSpans(s)) {
    argRanges(s, w.text, last, ranges, w);
    last = w.text;
  }
}

// scheme://user:password@host hides the password; scheme://token@host hides
// a token-like user part. Scanned by hand: the authority ends at the next
// '/', so every character is looked at a bounded number of times.
function userinfo(s, ranges) {
  for (let i = s.indexOf('://'); i >= 0; i = s.indexOf('://', i + 3)) {
    if (i === 0 || !/[A-Za-z0-9+.-]/.test(s[i - 1])) continue;
    let at = -1;
    let j = i + 3;
    for (; j < s.length; j++) {
      const c = s[j];
      if (c === '@') at = j;
      else if (c === '/' || c === '?' || c === '#' || c === '"' || c === "'" || c === '<' || c === '>' || c === '`' || /\s/.test(c)) break;
    }
    if (at <= i + 3) continue;
    const info = s.slice(i + 3, at);
    const colon = info.indexOf(':');
    if (colon >= 0) {
      const pw = info.slice(colon + 1);
      if (pw && !isPlaceholder(pw) && !pw.includes('••••')) ranges.push([i + 3 + colon + 1, at, true]);
    } else if (!isPlaceholder(info) && !info.includes('••••') && (info.length >= 20 || detect(info, 'token').length)) {
      ranges.push([i + 3, at, false]);
    }
  }
}

function query(s, ranges) {
  if (s.indexOf('=') < 0) return;
  for (const m of s.matchAll(QUERY)) {
    const [whole, k, v] = m;
    if (v && (isCredentialParam(k) || keyLooksSecret(k)) && !isPlaceholder(v) && !v.includes('••••')) {
      const at = m.index + whole.length - v.length;
      ranges.push([at, at + v.length, false]);
    }
  }
}

function patterns(s, ranges) {
  for (const p of PATTERNS) {
    let covered = 0;
    for (const m of s.matchAll(p.re)) {
      if (m.index < covered || (p.valid && !p.valid(m))) continue;
      let [start, end] = m.indices[p.group];
      if (p.name === 'Private key') {
        // The whole block, up to the end of its END line (or of the text).
        const e = s.indexOf('-----END', end);
        const close = e < 0 ? -1 : s.indexOf('-----', e + 8);
        end = close < 0 ? s.length : close + 5;
        covered = end;
      }
      ranges.push([start, end, false]);
    }
  }
}

/**
 * A lookup table of secrets that were found elsewhere, so that they are hidden
 * wherever they appear. Secrets shorter than `minLength` are left out.
 * @returns {{k: number, map: Map<string, string[]>, size: number} | null}
 */
export function secretIndex(secrets, minLength = 8) {
  const list = [...new Set([...(secrets || [])].map(String))].filter((x) => x.length >= minLength && !x.includes('••••'));
  if (!list.length) return null;
  let k = 8;
  for (const x of list) if (x.length < k) k = x.length;
  list.sort((x, y) => y.length - x.length);
  const map = new Map();
  for (const x of list) {
    const p = x.slice(0, k);
    if (!map.has(p)) map.set(p, []);
    map.get(p).push(x);
  }
  return { k, map, size: list.length };
}

/** Adds a range for every place in s[from, to) that holds a secret of the index. */
export function knownRanges(s, idx, ranges, from = 0, to = s.length) {
  if (!idx || to - from < idx.k) return;
  const { k, map } = idx;
  for (let i = from; i + k <= to; i++) {
    const list = map.get(s.slice(i, i + k));
    if (!list) continue;
    for (const x of list) {
      if (i + x.length <= to && s.startsWith(x, i)) { ranges.push([i, i + x.length, false]); i += x.length - 1; break; }
    }
  }
}

/**
 * The parts of `s` to hide, as [start, end, hideAll] ranges.
 * @param {string} s
 * @param {object} [o]
 * @param {string} [o.key] the env var, header or JSON key the value belongs to
 * @param {string} [o.prev] the argument before this one (a --flag gives the key)
 * @param {object} [o.known] a secretIndex() of secrets found elsewhere
 */
export function secretRanges(s, { key = '', prev = '', known = null } = {}) {
  const ranges = [];
  if (!s) return ranges;
  const outer = cache;
  cache = outer || new Map();
  try {
    const ctx = prev ? contextOf(lastWord(prev)) : null;
    const k = key || ctx?.key || '';
    if (k) judge(s, 0, s.length, k, ranges);
    args(s, prev, ranges);
    patterns(s, ranges);
    userinfo(s, ranges);
    query(s, ranges);
    words(s, ctx, ranges);
    if (known) knownRanges(s, known, ranges);
  } finally {
    cache = outer;
  }
  return ranges;
}

// With keepLines, a range keeps its line breaks, so masked config text still lines up.
function hidden(text, all, keepLines) {
  if (!keepLines || !text.includes('\n')) return all ? BULLETS : mask(text);
  return text.split('\n').map((part, i) => (part ? (i || all ? BULLETS : mask(part)) : '')).join('\n');
}

/**
 * `s` with the given ranges masked. Overlapping ranges are merged. With
 * keepLines (the default), a range that spans lines keeps its line breaks.
 */
export function applyRanges(s, ranges, keepLines = true) {
  if (!ranges.length) return s;
  const rs = ranges.filter((r) => r[1] > r[0]).sort((x, y) => x[0] - y[0] || y[1] - x[1]);
  let out = '';
  let pos = 0;
  let cur = null;
  const flush = () => { out += s.slice(pos, cur[0]) + hidden(s.slice(cur[0], cur[1]), cur[2], keepLines); pos = cur[1]; };
  for (const r of rs) {
    if (cur && r[0] < cur[1]) { cur[1] = Math.max(cur[1], r[1]); cur[2] = cur[2] || r[2]; continue; }
    if (cur) flush();
    cur = [Math.max(r[0], pos), r[1], r[2]];
  }
  if (cur) flush();
  return out + s.slice(pos);
}

/**
 * Text with every credential in it masked. Takes the same options as
 * secretRanges(). Returns null and undefined unchanged.
 */
export function maskString(text, opts) {
  if (text == null) return text;
  const s = String(text);
  return applyRanges(s, secretRanges(s, opts));
}

/** Only the secrets in `known` hidden, nothing else changed. */
export function maskKnown(text, known) {
  if (text == null || !known) return text;
  const s = String(text);
  const ranges = [];
  knownRanges(s, known, ranges);
  return applyRanges(s, ranges);
}

/** An argument list masked element by element, each with the one before it as context. */
export function maskArgv(list, { known = null } = {}) {
  return list.map((a, i) => maskString(String(a ?? ''), { prev: i ? String(list[i - 1] ?? '') : '', known }));
}

/** The secret strings in `s` (what maskString would hide). */
export function secretsOf(s, opts) {
  const str = String(s ?? '');
  return secretRanges(str, opts).map(([a, b]) => str.slice(a, b)).filter(Boolean);
}

/** The secret strings in an argument list. */
export function secretsOfArgv(list) {
  return list.flatMap((a, i) => secretsOf(a, { prev: i ? String(list[i - 1] ?? '') : '' }));
}
