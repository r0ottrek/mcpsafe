// Maps a finding's JSON path (e.g. mcpServers.github.env.TOKEN or
// servers.x.args[2]) back to a line number in the original config text,
// and builds masked source snippets for reports.
import { findSecrets, isPlaceholder, mask, SECRET_PATTERNS } from './secrets.js';

// ---------------- Tokenizer (JSON with comments) ----------------

const PUNCT = new Set(['{', '}', '[', ']', ':', ',']);

// Strings, punctuation and bare literals with their line numbers. Comments
// and whitespace are skipped, so commented-out config is never matched.
function tokenize(text) {
  const tokens = [];
  const n = text.length;
  let i = 0;
  let line = 1;
  while (i < n) {
    const c = text[i];
    if (c === '\n') { line++; i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r' || c === '\uFEFF') { i++; continue; }
    if (c === '/' && text[i + 1] === '/') { while (i < n && text[i] !== '\n') i++; continue; }
    if (c === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) { if (text[i] === '\n') line++; i++; }
      i += 2;
      continue;
    }
    if (c === '"') {
      // JSON strings cannot hold a raw newline, so an unterminated one ends at the line end.
      const start = i++;
      while (i < n && text[i] !== '"' && text[i] !== '\n') i += text[i] === '\\' && text[i + 1] !== '\n' ? 2 : 1;
      const closed = text[i] === '"';
      const raw = text.slice(start + 1, Math.min(i, n));
      if (closed) i++;
      let value = raw;
      try { value = JSON.parse(`"${raw}"`); } catch { /* keep raw */ }
      tokens.push({ type: 'str', start, end: i, raw, value, closed, line });
      continue;
    }
    if (PUNCT.has(c)) { tokens.push({ type: c, start: i, end: i + 1, line }); i++; continue; }
    const start = i;
    while (i < n && !/[\s"{}[\]:,]/.test(text[i]) && !(text[i] === '/' && (text[i + 1] === '/' || text[i + 1] === '*'))) i++;
    if (i === start) i++;
    tokens.push({ type: 'lit', start, end: i, line });
  }
  return tokens;
}

// Small cache: reports ask about the same file once per finding.
function cached(store, text, build) {
  if (store.has(text)) return store.get(text);
  const v = build(text);
  if (store.size >= 8) store.delete(store.keys().next().value);
  store.set(text, v);
  return v;
}

// ---------------- Line lookup ----------------

// Tree of objects and arrays with the line of every key and array element.
function buildTree(text) {
  const t = tokenize(text);
  let p = 0;
  const value = () => {
    const tok = t[p];
    if (!tok) return null;
    if (tok.type === '{') {
      p++;
      const node = { type: 'object', line: tok.line, members: new Map() };
      while (p < t.length) {
        const k = t[p];
        if (k.type === '}') { p++; break; }
        if (k.type !== 'str') { p++; continue; } // commas and anything malformed
        p++;
        if (t[p]?.type === ':') p++;
        const before = p;
        const v = value();
        if (p === before && t[p] && t[p].type !== '}' && t[p].type !== ',') p++;
        node.members.set(k.value, { line: k.line, node: v });
      }
      return node;
    }
    if (tok.type === '[') {
      p++;
      const node = { type: 'array', line: tok.line, items: [] };
      while (p < t.length) {
        const x = t[p];
        if (x.type === ']') { p++; break; }
        if (x.type === ',') { p++; continue; }
        if (x.type === '}') break;
        const before = p;
        node.items.push({ line: x.line, node: value() });
        if (p === before) p++;
      }
      return node;
    }
    if (tok.type === 'str' || tok.type === 'lit') { p++; return { type: 'value', line: tok.line }; }
    return null;
  };
  try { return value(); } catch { return null; }
}
const trees = new Map();

// The forms a key can take inside a finding's jsonPath: bare (mcpServers.x),
// quoted ("mcp.servers") or bracketed (projects["C:\\x"]), raw or JSON-escaped.
function keyForms(k) {
  const esc = JSON.stringify(k).slice(1, -1);
  return [...new Set([`["${k}"]`, `["${esc}"]`, `"${k}"`, `"${esc}"`, k])];
}

function resolve(node, rest, line) {
  rest = rest.replace(/^\./, '');
  if (!rest) return line;
  if (!node) return null;
  if (node.type === 'array') {
    const m = rest.match(/^\[(\d+)\]/);
    const item = m && node.items[Number(m[1])];
    return item ? resolve(item.node, rest.slice(m[0].length), item.line) : null;
  }
  if (node.type !== 'object') return null;
  // Server names and settings keys may contain dots, so try every key that the
  // path starts with, longest first, and keep the first one that resolves fully.
  const candidates = [];
  for (const [k, mem] of node.members) {
    for (const f of keyForms(k)) {
      if (rest.startsWith(f) && /^(?:$|[.[])/.test(rest.slice(f.length))) candidates.push([f.length, mem]);
    }
  }
  candidates.sort((a, b) => b[0] - a[0]);
  for (const [len, mem] of candidates) {
    const r = resolve(mem.node, rest.slice(len), mem.line);
    if (r != null) return r;
  }
  return null;
}

/** 1-based line of the key or array element at `jsonPath`, or null if it is not in the file. */
export function lineOf(text, jsonPath) {
  if (!text || !jsonPath) return null;
  const tree = cached(trees, text, buildTree);
  return tree ? resolve(tree, jsonPath, null) : null;
}

// ---------------- Masking ----------------

const BULLETS = '••••••••';
const jsonEsc = (s) => JSON.stringify(s).slice(1, -1);
const FLAG = /^--?([\w-]+)$/;
const KEY_EQ = /^-{0,2}([A-Za-z_][\w-]*)=(.+)$/s; // --api-key=xxx, -e API_KEY=xxx
const GLOBAL_PATTERNS = SECRET_PATTERNS.filter((p) => !p.group).map((p) => ({ ...p, re: new RegExp(p.re.source, `${p.re.flags}g`) }));

function replaceAll(s, secret) {
  const m = jsonEsc(mask(secret));
  for (const form of new Set([secret, jsonEsc(secret)])) if (form) s = s.split(form).join(m);
  return s;
}

// Context-free masking that is safe on any text: known token formats,
// user:password@ in URLs of any scheme, Authorization values and credential query parameters.
function maskPatterns(s) {
  for (const p of GLOBAL_PATTERNS) {
    s = s.replace(p.re, (...a) => {
      const m = a.slice(0, -2);
      if (p.valid && !p.valid(m)) return m[0];
      return mask(m[0]);
    });
  }
  s = s.replace(/([a-z][\w+.-]*:\/\/[^:/@\s"'\\]*:)([^@\s"'?#\\]+)@/gi, (w, a, pw) => (/^\d+(?:\/|$)/.test(pw) || isPlaceholder(pw) || pw === BULLETS ? w : `${a}${BULLETS}@`));
  s = s.replace(/\b(Bearer|Basic|Token)(\s+)([A-Za-z0-9._~+/=-]{16,})/g, (w, a, sp, v) => (isPlaceholder(v) ? w : `${a}${sp}${mask(v)}`));
  s = s.replace(/([?&](?:[\w-]*(?:key|token|secret|auth|password|sig|access)[\w-]*)=)([^&"'\s#\\]+)/gi, (w, k, v) => (isPlaceholder(v) ? w : `${k}${mask(v)}`));
  return s;
}

// Everything a check could flag in one string value, given its context.
function secretsIn(value, keyName) {
  const dets = [...findSecrets(value, keyName)];
  const eq = value.match(KEY_EQ);
  if (eq) dets.push(...findSecrets(eq[2], eq[1]));
  return dets;
}

// Mask one string token's raw (still JSON-escaped) content.
function maskRaw(raw, value, dets, known) {
  if (dets.some((d) => d.type === 'Private key')) return jsonEsc(mask(value));
  const all = [...new Set([...dets.map((d) => d.secret), ...known])].filter(Boolean).sort((a, b) => b.length - a.length);
  let s = raw;
  for (const secret of all) s = replaceAll(s, secret);
  return maskPatterns(s);
}

// For each string value: the key it belongs to, or the --flag right before it in an array.
function withContext(tokens) {
  const out = [];
  for (let j = 0; j < tokens.length; j++) {
    const tok = tokens[j];
    if (tok.type !== 'str') continue;
    const isKey = tokens[j + 1]?.type === ':';
    let keyName = '';
    const prev = tokens[j - 1];
    if (!isKey && prev?.type === ':' && tokens[j - 2]?.type === 'str') keyName = tokens[j - 2].value;
    else if (!isKey && prev?.type === ',' && tokens[j - 2]?.type === 'str' && tokens[j - 3]?.type !== ':') {
      const f = String(tokens[j - 2].value).match(FLAG);
      if (f) keyName = f[1];
    }
    out.push({ tok, isKey, keyName });
  }
  return out;
}

function maskTokens(text, known = new Set()) {
  const strings = withContext(tokenize(text));
  const dets = strings.map((x) => (x.isKey ? [] : secretsIn(String(x.tok.value), x.keyName)));
  // Long secrets are also hidden wherever else they appear (repeats, comments, other strings).
  const all = new Set(known);
  for (const d of dets.flat()) if (d.secret && d.secret.length >= 8) all.add(d.secret);
  const free = (s) => {
    for (const secret of [...all].sort((a, b) => b.length - a.length)) s = replaceAll(s, secret);
    return maskPatterns(s);
  };
  let out = '';
  let pos = 0;
  strings.forEach(({ tok }, j) => {
    out += free(text.slice(pos, tok.start));
    out += `"${maskRaw(tok.raw, String(tok.value), dets[j], all)}${tok.closed ? '"' : ''}`;
    pos = tok.end;
  });
  return out + free(text.slice(pos));
}
const masked = new Map();

/** The whole config text with every secret masked. Line breaks are kept, so lines still line up. */
export function maskText(text) {
  if (!text) return text;
  return cached(masked, text, (t) => maskTokens(t));
}

/**
 * Mask secrets in one line of JSON. Without the file around it, a value that
 * follows a --flag on another line cannot be recognised, so prefer snippet()
 * or maskText() when the whole file is available.
 */
export function maskLine(line) {
  return maskTokens(String(line));
}

/** Lines around `line` (1-based), masked. Returns [{n, text, hit}] */
export function snippet(text, line, context = 2) {
  if (!text || !line) return null;
  const lines = maskText(text).split('\n');
  const from = Math.max(1, line - context);
  const to = Math.min(lines.length, line + context);
  const out = [];
  for (let n = from; n <= to; n++) out.push({ n, text: lines[n - 1].replace(/\t/g, '  '), hit: n === line });
  return out;
}
