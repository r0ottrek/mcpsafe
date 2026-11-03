// Maps a finding's JSON path (e.g. mcpServers.github.env.TOKEN or
// servers.x.args[2]) back to a line number in the original config text,
// and builds masked source snippets for reports.
import { detectSecret, mask } from './secrets.js';

const STRING = /"((?:[^"\\]|\\.)*)"/g;

export function lineOf(text, jsonPath) {
  if (!text || !jsonPath) return null;
  const tokens = jsonPath.match(/"[^"]+"|\[\d+\]|[^.[\]"]+/g) || [];
  let idx = 0;
  let found = false;
  for (const t of tokens) {
    if (/^\[\d+\]$/.test(t)) {
      // Step into an array: skip to the n-th string after the opening bracket.
      const open = text.indexOf('[', idx);
      if (open < 0) continue;
      const n = Number(t.slice(1, -1));
      STRING.lastIndex = open;
      let m;
      for (let i = 0; i <= n; i++) m = STRING.exec(text);
      if (m) { idx = m.index; found = true; }
      continue;
    }
    const key = t.replace(/^"|"$/g, '');
    const re = new RegExp(`"${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\s*:`, 'g');
    re.lastIndex = idx;
    const m = re.exec(text);
    if (m) { idx = m.index; found = true; }
  }
  return found ? text.slice(0, idx).split('\n').length : null;
}

// Replace secret-looking string values in one line of JSON with a masked form.
export function maskLine(line) {
  let prev = null;
  return line.replace(STRING, (whole, value, offset) => {
    const after = line.slice(offset + whole.length);
    const isKey = /^\s*:/.test(after);
    if (isKey) { prev = value; return whole; }
    const det = detectSecret(value, prev || '');
    prev = null;
    if (det && /^Database/.test(det.type)) return `"${value.replace(/(:\/\/[^:/@\s]+:)[^@\s]+@/, '$1••••••••@')}"`;
    if (det) return `"${value.replace(det.match, mask(det.match))}"`;
    // Credentials in URL query strings
    return whole.replace(/([?&](?:[\w-]*(?:key|token|secret|auth|password|sig|access)[\w-]*)=)([^&"]+)/gi, (_, k, v) => `${k}${mask(v)}`);
  });
}

/** Lines around `line` (1-based), masked. Returns [{n, text, hit}] */
export function snippet(text, line, context = 2) {
  if (!text || !line) return null;
  const lines = text.split('\n');
  const from = Math.max(1, line - context);
  const to = Math.min(lines.length, line + context);
  const out = [];
  for (let n = from; n <= to; n++) out.push({ n, text: maskLine(lines[n - 1].replace(/\t/g, '  ')), hit: n === line });
  return out;
}
