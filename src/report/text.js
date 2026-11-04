// Text helpers shared by the reports: making untrusted strings safe to print,
// and measuring and cutting text by the columns it takes in a terminal.

// C0 and C1 control characters and DEL. Characters above U+00FF also match
// here, and FORMAT below picks out the ones to escape: the Unicode line and
// paragraph separators and the bidirectional embedding, override and isolate
// marks (U+2028-2029, U+202A-202E, U+2066-2069).
// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x1f\x7f-\x9f]|[^\x00-\xff]/g;
const FORMAT = (n) => (n >= 0x2028 && n <= 0x202e) || (n >= 0x2066 && n <= 0x2069);

/**
 * Make a string from a config file or a server safe to print on one line.
 * Control characters are shown as \xNN or \uNNNN, so they cannot move the
 * cursor, set the window title, hide text or start a new output line (CI
 * runners read lines that start with "::" as commands). A tab becomes a space.
 */
export function safe(s) {
  return String(s ?? '').replace(CONTROL, (ch) => {
    if (ch === '\t') return ' ';
    const n = ch.charCodeAt(0);
    if (n > 0xff && !FORMAT(n)) return ch;
    return n <= 0xff ? `\\x${n.toString(16).padStart(2, '0')}` : `\\u${n.toString(16).padStart(4, '0')}`;
  });
}

// eslint-disable-next-line no-control-regex
const SGR = /\x1b\[[0-9;]*m/g;

// Columns one code point takes in a terminal: 0 for combining marks and
// joiners, 2 for East Asian wide and fullwidth characters and most emoji.
function cpWidth(cp) {
  if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060 || cp === 0xfeff
    || (cp >= 0x0300 && cp <= 0x036f) || (cp >= 0x1ab0 && cp <= 0x1aff) || (cp >= 0x1dc0 && cp <= 0x1dff)
    || (cp >= 0x20d0 && cp <= 0x20ff) || (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xfe20 && cp <= 0xfe2f)
    || (cp >= 0x1f3fb && cp <= 0x1f3ff) || (cp >= 0xe0000 && cp <= 0xe01ef)) return 0;
  if ((cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0x303e) || (cp >= 0x3041 && cp <= 0x33ff)
    || (cp >= 0x3400 && cp <= 0x4dbf) || (cp >= 0x4e00 && cp <= 0x9fff) || (cp >= 0xa000 && cp <= 0xa4cf)
    || (cp >= 0xac00 && cp <= 0xd7a3) || (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0xfe30 && cp <= 0xfe4f)
    || (cp >= 0xff00 && cp <= 0xff60) || (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f1e6 && cp <= 0x1f1ff)
    || (cp >= 0x1f300 && cp <= 0x1f64f) || (cp >= 0x1f680 && cp <= 0x1f6ff) || (cp >= 0x1f900 && cp <= 0x1faff)
    || (cp >= 0x20000 && cp <= 0x3fffd)) return 2;
  return 1;
}

/** Columns a string takes in a terminal, ignoring colour codes. */
export function dispWidth(s) {
  let w = 0;
  for (const ch of String(s).replace(SGR, '')) w += cpWidth(ch.codePointAt(0));
  return w;
}

/**
 * Split plain text after at most `w` columns, on a code point boundary. With
 * `atLeastOne`, the first code point is kept even when it is wider than `w`,
 * so a caller that loops over the rest always makes progress.
 */
export function splitW(s, w, atLeastOne = true) {
  let used = 0;
  let i = 0;
  const str = String(s);
  for (const ch of str) {
    const cw = cpWidth(ch.codePointAt(0));
    if (used + cw > w && (i > 0 || !atLeastOne)) break;
    used += cw;
    i += ch.length;
  }
  return [str.slice(0, i), str.slice(i)];
}

/** Plain text cut to at most `w` columns, ending in "…" when cut. */
export function truncW(s, w) {
  const str = String(s);
  if (dispWidth(str) <= w) return str;
  if (w <= 1) return w === 1 ? '…' : '';
  return `${splitW(str, w - 1, false)[0]}…`;
}

/** Text padded with spaces to `w` columns. */
export function padW(s, w) {
  return `${s}${' '.repeat(Math.max(0, w - dispWidth(s)))}`;
}
