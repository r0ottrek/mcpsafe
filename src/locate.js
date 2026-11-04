// Maps a finding's JSON path (e.g. mcpServers.github.env.TOKEN or
// servers.x.args[2]) back to a line number in the original config text,
// and builds masked source snippets for reports.
import { applyRanges, knownRanges, maskString, secretIndex, secretRanges } from './mask.js';

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
      let parsed = false;
      try { value = JSON.parse(`"${raw}"`); parsed = true; } catch { /* keep raw */ }
      tokens.push({ type: 'str', start, end: i, raw, value, parsed, closed, line });
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
// The masking itself is in src/mask.js. This part walks the config's tokens
// so that each string is judged with its JSON key, or with the array element
// (a --flag) right before it.

const jsonEsc = (s) => JSON.stringify(s).slice(1, -1);

// For each string value: the key it belongs to, or the array element before it.
function withContext(tokens) {
  const out = [];
  for (let j = 0; j < tokens.length; j++) {
    const tok = tokens[j];
    if (tok.type !== 'str') continue;
    const isKey = tokens[j + 1]?.type === ':';
    let key = '';
    let prev = '';
    const before = tokens[j - 1];
    if (!isKey && before?.type === ':' && tokens[j - 2]?.type === 'str') key = String(tokens[j - 2].value);
    else if (!isKey && before?.type === ',' && tokens[j - 2]?.type === 'str' && tokens[j - 3]?.type !== ':') prev = String(tokens[j - 2].value);
    out.push({ tok, isKey, key, prev });
  }
  return out;
}

// Pass 1: the secrets in each string, judged in its context, and an index of
// all of them, so that a repeat anywhere else in the file is hidden too.
function analyze(text) {
  const strings = withContext(tokenize(text));
  const found = strings.map(({ tok, isKey, key, prev }) => (isKey ? [] : secretRanges(String(tok.value), { key, prev })));
  const all = new Set();
  strings.forEach(({ tok }, j) => {
    const v = String(tok.value);
    for (const [a, b] of found[j]) {
      const secret = v.slice(a, b);
      if (secret.length >= 8) { all.add(secret); all.add(jsonEsc(secret)); }
    }
  });
  return { strings, found, index: secretIndex(all) };
}
const analyses = new Map();

/**
 * Every secret found in a config's text, as a lookup table for the `known`
 * option of the functions in src/mask.js, or null when there is none.
 */
export function configSecrets(text) {
  if (!text) return null;
  return cached(analyses, text, analyze).index;
}

// Only punctuation and white space between two strings: nothing to mask.
const PLAIN = /^[\s{}[\]:,]*$/;

// Pass 2: each string with its own and the known secrets hidden. Text outside
// strings (comments, bare values) is masked as free text.
function maskTokens(text, a) {
  const free = (g) => (PLAIN.test(g) ? g : maskString(g, { known: a.index }));
  let out = '';
  let pos = 0;
  a.strings.forEach(({ tok }, j) => {
    out += free(text.slice(pos, tok.start));
    const v = String(tok.value);
    const ranges = a.found[j].slice();
    knownRanges(v, a.index, ranges);
    if (!ranges.length) out += text.slice(tok.start, tok.end);
    else {
      // A JSON string holds no raw line break, so a masked key block becomes one short value.
      const m = applyRanges(v, ranges, false);
      out += `"${tok.parsed ? jsonEsc(m) : m}${tok.closed ? '"' : ''}`;
    }
    pos = tok.end;
  });
  return out + free(text.slice(pos));
}
const masked = new Map();
const maskedLines = new Map();

/** The whole config text with every secret masked. Line breaks are kept, so lines still line up. */
export function maskText(text) {
  if (!text) return text;
  return cached(masked, text, (t) => maskTokens(t, cached(analyses, t, analyze)));
}

/**
 * Mask secrets in one line of JSON. Without the file around it, a value that
 * follows a --flag on another line cannot be recognised, so prefer snippet()
 * or maskText() when the whole file is available.
 */
export function maskLine(line) {
  const t = String(line);
  return maskTokens(t, analyze(t));
}

/** Lines around `line` (1-based), masked. Returns [{n, text, hit}] */
export function snippet(text, line, context = 2) {
  if (!text || !line) return null;
  const lines = cached(maskedLines, text, (t) => maskText(t).split('\n'));
  const from = Math.max(1, line - context);
  const to = Math.min(lines.length, line + context);
  const out = [];
  for (let n = from; n <= to; n++) out.push({ n, text: lines[n - 1].replace(/\t/g, '  '), hit: n === line });
  return out;
}
