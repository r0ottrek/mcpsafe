// Detects credentials pasted directly into config values.

// Loopback hosts and the default passwords that local database containers and
// tools ship with (the Supabase CLI uses postgres:postgres@127.0.0.1:54322).
// A URL with one of these on a loopback host is a local dev default that grants
// nothing beyond the machine, so it is not reported. The same password on any
// other host, or any other password on loopback, still is.
const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1|0\.0\.0\.0|host\.docker\.internal)$/i;
const DEV_DB_PASSWORDS = new Set([
  'postgres', 'password', 'pass', 'root', 'example', 'secret', 'admin', 'dev', 'test', 'mysql', 'mariadb',
  'redis', 'redispw', 'mongo', 'mongodb', 'guest', 'clickhouse',
]);

function isLocalDevDb(m) {
  // locate.js calls `valid` from String.replace, where the match has no index.
  if (typeof m.index !== 'number' || typeof m.input !== 'string') return false;
  if (!DEV_DB_PASSWORDS.has(m[1].toLowerCase())) return false;
  const rest = m.input.slice(m.index + m[0].length, m.index + m[0].length + 256);
  const host = rest.startsWith('[') ? rest.slice(0, rest.indexOf(']') + 1) : rest.split(/[:/?#,\s]/)[0];
  return LOOPBACK.test(host);
}

// `group` names the capture group that holds the secret itself (default: the
// whole match). `valid` rejects matches that only look like the pattern.
// The user and password runs are bounded so that a long run of "mysql://a:"
// cannot make the search quadratic.
const DB_URL = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse)(?:\+\w+)?:\/\/[^:\s/@]{0,256}:([^@\s?#]{3,256})@/;

export const SECRET_PATTERNS = [
  { name: 'Anthropic API key', re: /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}/ },
  // Real keys are random mixed case with digits; kebab-case names such as
  // "task-management-..." are not.
  { name: 'OpenAI API key', re: /(?<![A-Za-z0-9])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/, valid: (m) => /[A-Z]/.test(m[0]) && /\d/.test(m[0]) },
  { name: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/ },
  { name: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/ },
  { name: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Stripe secret key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/ },
  { name: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{30,}\b/ },
  { name: 'Notion token', re: /\b(?:secret|ntn)_[A-Za-z0-9]{40,}\b/ },
  { name: 'Linear API key', re: /\blin_api_[A-Za-z0-9]{30,}\b/ },
  { name: 'Private key', re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/ },
  // A password may contain '/', but "host:5432/db" before a later '@' is a port and a path.
  { name: 'Database URL with password', re: DB_URL, group: 1, valid: (m) => !/^\d+(?:\/|$)/.test(m[1]) && !isPlaceholder(m[1]) && !isLocalDevDb(m) },
];

const SECRET_KEY_NAME = /(api[_-]?key|apikey|token(?!iz)|secret|passw(or)?d|passwd|pwd|passphrase|credential|private[_-]?key|access[_-]?key|bearer)/i;
// Whole words only, so OAUTH, AUTHOR and AUTH0 do not count.
const SECRET_KEY_WORDS = new Set(['auth', 'authorization', 'pat']);
// Key names whose last word says the value is a setting, not the secret itself
// (TOKEN_URL, AUTH_PROVIDER, SECRET_ID, SECRET_ARN, TOKEN_ENV_VAR, ...).
const NON_SECRET_KEY_END = new Set([
  'path', 'file', 'filename', 'dir', 'directory', 'folder', 'url', 'uri', 'endpoint', 'domain', 'host', 'hostname', 'port',
  'scope', 'scopes', 'provider', 'method', 'mode', 'type', 'email', 'name', 'id', 'user', 'username', 'region', 'issuer',
  'audience', 'enabled', 'limit', 'ttl', 'expiry', 'version', 'format', 'size', 'count',
  'arn', 'ref', 'reference', 'resource', 'env', 'var', 'variable', 'source', 'server', 'permissions', 'roles', 'template',
]);

function keyWords(key) {
  return String(key).split(/[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])/).filter(Boolean).map((w) => w.toLowerCase());
}

function keyLooksSecret(key) {
  if (!key) return false;
  const words = keyWords(key);
  if (!words.length || NON_SECRET_KEY_END.has(words[words.length - 1])) return false;
  return SECRET_KEY_NAME.test(key) || words.some((w) => SECRET_KEY_WORDS.has(w));
}

// Top-level domains a configured host name plausibly ends in (any two-letter
// country code counts too). "prod.k9x2m7q4z8w1.abc" is a dotted token, not a host.
const TLDS = new Set([
  'com', 'net', 'org', 'io', 'dev', 'app', 'ai', 'co', 'cloud', 'info', 'biz', 'edu', 'gov', 'mil', 'int', 'xyz', 'tech',
  'site', 'online', 'run', 'page', 'host', 'services', 'systems', 'internal', 'local', 'localhost', 'lan', 'corp', 'home',
  'test', 'example', 'invalid', 'svc', 'cluster', 'aws', 'azure', 'google', 'microsoft',
]);

const CAMEL = /^[A-Z]?[a-z]+(?:[A-Z][a-z]+)*\d{0,2}$/;

// One word of an identifier, scope or path: "read", "Mail", "ReadWrite",
// "oauth2", "GCP", "Reader2", "2024". Random keys mix case and digits, so a
// camelCase word allows digits only at its end, needs a vowel in every part and
// parts of three letters or more on average ("yzuEpihKowqaCxgb" is not one).
function wordyToken(t) {
  if (/^[a-z]+\d{0,2}$/.test(t) || /^[A-Z]{1,6}\d{0,2}$/.test(t) || /^\d{1,4}$/.test(t)) return true;
  if (!CAMEL.test(t)) return false;
  const parts = t.replace(/\d+$/, '').split(/(?=[A-Z])/);
  return parts.every((p) => /[aeiouy]/i.test(p)) && parts.length * 3 <= t.length;
}

// Values that are clearly not credentials, whatever their key is called.
function looksLikeSetting(v, key) {
  const passKey = /pass|pwd/i.test(key);
  if (/^[a-z][\w+.-]*:\/\//i.test(v)) return true; // any URL; DB URLs are covered by the pattern above
  if (/^[./~]/.test(v) || /^[A-Za-z]:[\\/]/.test(v) || v.startsWith('\\\\')) return true; // paths
  if (/[\\/]/.test(v) && /\.[A-Za-z0-9]{1,5}$/.test(v.split(/[\\/]/).pop())) return true; // relative path to a file
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return true; // email address
  // References to a secret held elsewhere: AWS ARNs, GCP Secret Manager names,
  // Azure Key Vault references. They name the secret; they are not the secret.
  if (/^arn:aws[\w-]*:/i.test(v) || /^projects\/[^/]+\/secrets\//.test(v) || /^@Microsoft\.KeyVault\(/i.test(v)) return true;
  // An environment variable name (--token-env-var GITHUB_PERSONAL_ACCESS_TOKEN).
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) return true;
  // Host name, in any case (Login.MicrosoftOnline.com), with a real-looking TLD.
  const host = v.match(/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.([A-Za-z]{2,24})(?::\d{1,5})?(?:\/[^\s]*)?$/);
  if (host && (host[1].length === 2 || TLDS.has(host[1].toLowerCase()))) return true;
  // A passphrase looks like the rules below, so keep them away from password keys.
  if (passKey) return false;
  // Relative paths: Windows style (keys\id_ed25519) or under a usual folder name.
  if (/^[\w .-]+(?:\\[\w .-]+)+\\?$/.test(v)) return true;
  if (/^(?:secrets?|keys?|credentials?|creds|certs?|config|conf|\.?ssh|private|home|users?|etc|var|opt|data|tmp)[\\/]/i.test(v)) return true;
  // Identifiers, enum values, scope lists and secret ids made of ordinary words:
  // "azure-active-directory", "read:user,repo,gist", "Mail.Read,Files.ReadWrite",
  // "EnvironmentCredential", "prod/mcp/database-credentials".
  if (/^[A-Za-z0-9._:,/\\-]+$/.test(v)) {
    const tokens = v.split(/[._:,/\\-]+/).filter(Boolean);
    if (tokens.every(wordyToken) && (tokens.length >= 2 || /[a-z][A-Z]/.test(v))) return true;
  }
  return false;
}

// ---- ${...} references ----

// Shell and Claude Code operators whose right-hand side is literal text that is
// committed with the config: ${VAR:-default}, ${VAR-default}, ${VAR:=x},
// ${VAR=x}, ${VAR:?message}, ${VAR?message}, ${VAR:+alt}, ${VAR+alt}.
const OP_CHARS = '-=?+';
const isNameChar = (c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c === '_';

/**
 * Expands ${...} references in one left-to-right pass (linear in the length,
 * whatever the nesting). A reference with a default operator becomes its
 * default text; any other reference (${VAR}, ${env:X}, ${input:id}) becomes
 * nothing; an unclosed "${" stays as literal text.
 * @returns {{text: string, defaults: string[]}} the expanded text and every
 *   default value found, inner ones included
 */
function parseRefs(str) {
  const s = String(str);
  const stack = []; // open references: {lit, phase: 'name'|'value'|'other', name, op, val}
  const defaults = [];
  let out = '';
  const emit = (text, literal = text) => {
    const f = stack[stack.length - 1];
    if (!f) { out += text; return; }
    f.lit += literal;
    if (f.phase === 'value') f.val += text;
    else if (f.phase === 'name') f.phase = 'other';
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '$' && s[i + 1] === '{') {
      stack.push({ lit: '${', phase: 'name', name: '', op: '', val: '' });
      i += 2;
      continue;
    }
    const f = stack[stack.length - 1];
    if (!f) {
      // Copy plain text up to the next "${" in one step.
      const next = s.indexOf('${', i);
      const end = next === -1 ? s.length : next;
      out += s.slice(i, end);
      i = end;
      continue;
    }
    if (c === '}') {
      stack.pop();
      const value = f.op ? f.val : '';
      if (f.op && value) defaults.push(value);
      emit(value, value);
      i++;
      continue;
    }
    if (f.phase === 'name') {
      if (isNameChar(c)) { f.name += c; f.lit += c; i++; continue; }
      if (f.name && c === ':' && OP_CHARS.includes(s[i + 1] || '\0')) { f.op = c + s[i + 1]; f.lit += f.op; f.phase = 'value'; i += 2; continue; }
      if (f.name && OP_CHARS.includes(c)) { f.op = c; f.lit += c; f.phase = 'value'; i++; continue; }
      f.phase = 'other';
    }
    // Inside a reference: copy up to the next special character in one step.
    let j = i + 1;
    while (j < s.length && s[j] !== '}' && !(s[j] === '$' && s[j + 1] === '{')) j++;
    const chunk = s.slice(i, j);
    f.lit += chunk;
    if (f.phase === 'value') f.val += chunk;
    i = j;
  }
  // References that never closed are literal text.
  while (stack.length) {
    const f = stack.pop();
    const parent = stack[stack.length - 1];
    if (!parent) out += f.lit;
    else { parent.lit += f.lit; if (parent.phase === 'value') parent.val += f.lit; }
  }
  return { text: out, defaults: [...new Set(defaults)] };
}

// Replace variable references by their default value (or nothing), so that a
// literal committed next to a reference is still checked.
export function expandRefs(s) {
  return parseRefs(s).text;
}

// ---- Placeholders ----

// Words that mark a template value copied from a README: "xoxb-your-bot-token",
// "fc-YOUR_API_KEY", "ghp_YourTokenGoesHere", "sk-proj-REPLACE_ME".
const PLACEHOLDER_WORDS = new Set([
  'your', 'yours', 'here', 'replace', 'example', 'changeme', 'changeit', 'dummy', 'placeholder', 'redacted', 'insert',
  'fixme', 'sample',
]);

// Whole words only (split at separators, case changes and digits), so a random
// token that happens to contain "here" or "xxxx" inside a longer run still counts.
function hasPlaceholderWord(s) {
  if (s.includes('...') || s.includes('…')) return true; // "sk-ant-api03-..."
  for (const w of s.split(/[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])/)) {
    const l = w.toLowerCase();
    if (PLACEHOLDER_WORDS.has(l) || (l.length >= 4 && /^x+$/.test(l))) return true;
  }
  return false;
}

// `s` has its ${...} references expanded already.
function placeholderText(s) {
  s = s.trim();
  if (!s) return true;
  if (/^\$[A-Za-z_]\w*$/.test(s)) return true; // $VAR
  if (/^%[A-Za-z_]\w*%$/.test(s)) return true; // %VAR%
  if (/^(?:\$env:|env:)[A-Za-z_]\w*$/i.test(s)) return true; // PowerShell $env:VAR, env:VAR
  if (/^<.*>$/.test(s) || /<[A-Za-z_][\w .-]*>/.test(s)) return true; // <your-token>, xoxb-<token>
  if (/\{\{[^{}]*\}\}/.test(s)) return true; // {{GITHUB_TOKEN}}
  if (/^(your|my|insert|replace|enter|put|add)[\s_-]/i.test(s)) return true;
  if (/(placeholder|changeme|example|dummy|redacted|xxxx|\*\*\*\*|here$)/i.test(s)) return true;
  if (/^(true|false|null|none|\d+)$/i.test(s)) return true;
  return hasPlaceholderWord(s);
}

export function isPlaceholder(v) {
  const s = String(v);
  // ${VAR}, ${env:VAR}, ${input:id}: a placeholder only if nothing literal is left
  return placeholderText(s.includes('${') ? expandRefs(s) : s);
}

export function entropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const n of Object.values(freq)) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

export function mask(v) {
  const s = String(v);
  if (s.length <= 8) return '••••••••';
  return `${s.slice(0, 4)}${'•'.repeat(8)}`;
}

const globals = new Map();
function globalRe(re) {
  if (!globals.has(re)) globals.set(re, new RegExp(re.source, `${re.flags}g`));
  return globals.get(re);
}

/**
 * Every credential found in one value.
 * `match` is what the finding shows (masked); `secret` is the exact text to hide.
 * @param {string} value
 * @param {string} [keyName] the env var / header / arg name the value belongs to
 * @returns {{type: string, confidence: 'high'|'medium', match: string, secret: string}[]}
 */
export function findSecrets(value, keyName = '') {
  if (value == null) return [];
  const raw = String(value);
  const refs = raw.includes('${') ? parseRefs(raw) : null;
  const s = refs ? refs.text : raw;
  // A single-word value is judged as a whole. A value with spaces (a command
  // line, a header) can hold a real token next to template text, so each
  // match is judged on its own instead.
  if (placeholderText(s) && (!s.trim() || !/\s/.test(s.trim()))) return [];
  const out = [];
  for (const p of SECRET_PATTERNS) {
    for (const m of s.matchAll(globalRe(p.re))) {
      if (p.valid && !p.valid(m)) continue;
      // A private key is the whole value, not just its header line.
      const secret = p.name === 'Private key' ? s : m[p.group || 0];
      if (placeholderText(p.name === 'Private key' ? s : m[0])) continue;
      out.push({ type: p.name, confidence: 'high', match: m[0], secret });
    }
  }
  if (out.length) return out;
  // Authorization: Bearer <literal>
  const bearer = s.trim().match(/^(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{16,})$/i);
  if (bearer && !placeholderText(bearer[1])) return [{ type: 'Authorization header credential', confidence: 'high', match: bearer[1], secret: bearer[1] }];
  // Generic: secret-looking key name with a random-looking value. When the value
  // mixes in ${...} references, only a literal default value is judged, so that
  // "${HOME}/.config/x" or "https://${HOST}/api" are not.
  if (!keyLooksSecret(keyName)) return out;
  const candidates = refs ? refs.defaults : [s];
  for (const c of candidates) {
    if (c.length >= 12 && !/\s/.test(c) && !placeholderText(c) && !looksLikeSetting(c, keyName) && entropy(c) >= 3.2) {
      out.push({ type: `Credential in ${keyName}`, confidence: 'medium', match: c, secret: c });
    }
  }
  return out;
}

/**
 * @param {string} value
 * @param {string} [keyName] the env var / header / arg name the value belongs to
 * @returns {{type: string, confidence: 'high'|'medium', match: string, secret: string}|null}
 */
export function detectSecret(value, keyName = '') {
  return findSecrets(value, keyName)[0] ?? null;
}
