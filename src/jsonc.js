// Tolerant JSON parser: accepts comments and trailing commas (JSONC),
// which VS Code, Cursor and Claude config files often contain.

const isSpace = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r';

// Turns JSONC into JSON of the same length: comments and trailing commas
// become spaces (line breaks are kept), so offsets, line numbers and string
// contents are those of the original text.
export function stripJsonc(text) {
  const out = [];
  let i = 0;
  let inString = false;
  let comma = -1; // index in out of a comma not yet followed by a value
  while (i < text.length) {
    const c = text[i];
    const n = text[i + 1];
    if (inString) {
      out.push(c);
      if (c === '\\' && n !== undefined) { out.push(n); i += 2; continue; }
      if (c === '"') inString = false;
      i++;
      continue;
    }
    if (c === '/' && n === '/') {
      while (i < text.length && text[i] !== '\n' && text[i] !== '\r') { out.push(' '); i++; }
      continue;
    }
    if (c === '/' && n === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end < 0 ? text.length : end + 2;
      for (; i < stop; i++) out.push(text[i] === '\n' || text[i] === '\r' ? text[i] : ' ');
      continue;
    }
    if (!isSpace(c)) {
      if ((c === '}' || c === ']') && comma >= 0) out[comma] = ' ';
      comma = c === ',' ? out.length : -1;
      if (c === '"') inString = true;
    }
    out.push(c);
    i++;
  }
  return out.join('');
}

const NOT_VALID = ' is not valid JSON';

// Newer Node versions quote up to about 20 characters of the text in the
// message ('Unexpected token 'Z', "{"a":Zq8Lm2..."... is not valid JSON'),
// which can be part of a secret. The quote is replaced by its line number.
function withoutExcerpt(err, parsed) {
  const msg = err.message;
  const end = msg.lastIndexOf(NOT_VALID);
  // The quote is ', "text"' or ', ..."text"...', after the token.
  const q = msg.indexOf(', ');
  if (end < 0 || q < 0 || q > end) return;
  let ex = msg.slice(q + 2, end);
  if (ex.startsWith('...')) ex = ex.slice(3);
  if (ex.endsWith('...')) ex = ex.slice(0, -3);
  ex = ex.length >= 2 && ex.startsWith('"') && ex.endsWith('"') ? ex.slice(1, -1) : '';
  const at = ex ? parsed.indexOf(ex) : -1;
  const line = at < 0 ? 0 : parsed.slice(0, at).split(/\r\n|\r|\n/).length;
  err.message = `${msg.slice(0, q)} in JSON${line ? ` (near line ${line})` : ''}${msg.slice(end + NOT_VALID.length)}`;
}

// Adds "(line L column C)" to a JSON.parse message that only gives a
// position (older Node versions).
function withLine(err, text, parsed = text) {
  withoutExcerpt(err, parsed);
  const m = /position (\d+)/.exec(err.message);
  if (m && !/line \d+/.test(err.message)) {
    const before = text.slice(0, Number(m[1]));
    const line = before.split(/\r\n|\r|\n/).length;
    const column = before.length - Math.max(before.lastIndexOf('\n'), before.lastIndexOf('\r'));
    err.message += ` (line ${line} column ${column})`;
  }
  return err;
}

export function parseJsonc(text) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  try {
    return JSON.parse(text);
  } catch {
    const stripped = stripJsonc(text);
    try {
      return JSON.parse(stripped);
    } catch (e) {
      throw withLine(e, text, stripped);
    }
  }
}
