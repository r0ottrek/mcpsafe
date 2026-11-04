// Detects credentials pasted directly into config values.

// Loopback hosts and the default passwords that local database containers and
// tools ship with (the Supabase CLI uses postgres:postgres@127.0.0.1:54322,
// the postgres image's Docker Hub example uses mysecretpassword). A password
// that repeats the user name (app:app, root:root) is the same kind of local
// default. A URL with one of these on a loopback host grants nothing beyond
// the machine, so it is not reported. The same password on any other host, or
// any other password on loopback, still is.
const LOOPBACK = /^(?:(?:[a-z0-9-]+\.)*localhost\.?|127(?:\.\d{1,3}){3}|\[::1\]|::1|0\.0\.0\.0|host\.docker\.internal)$/i;
const DEV_DB_PASSWORDS = new Set([
  'postgres', 'password', 'pass', 'root', 'example', 'secret', 'admin', 'dev', 'test', 'mysql', 'mariadb',
  'redis', 'redispw', 'mongo', 'mongodb', 'guest', 'clickhouse', 'mysecretpassword',
]);

// The host of one entry of a host list: "localhost:5432" -> "localhost", "[::1]:5432" -> "[::1]".
function hostPart(h) {
  if (h.startsWith('[')) { const e = h.indexOf(']'); return e < 0 ? h : h.slice(0, e + 1); }
  const c = h.indexOf(':');
  return c < 0 ? h : h.slice(0, c);
}

// The user name of a scheme://user:password@ match whose password is `pw`.
function userOf(m, pw) {
  const at = m[0].indexOf('://');
  return m[0].slice(at + 3, m[0].length - pw.length - 2);
}

function isLocalDevDb(m, pw = m[1]) {
  // locate.js calls `valid` from String.replace, where the match has no index.
  if (typeof m.index !== 'number' || typeof m.input !== 'string') return false;
  const p = pw.toLowerCase();
  if (!DEV_DB_PASSWORDS.has(p) && p !== userOf(m, pw).toLowerCase()) return false;
  // The rest of the URL (bounded, so many matches in one text stay linear).
  const after = m.input.slice(m.index + m[0].length, m.index + m[0].length + 1024);
  const end = after.search(/[\s"'<>`]/);
  const rest = end < 0 ? after : after.slice(0, end);
  // Every host of a multi-host URL (replica sets, libpq host lists) must be loopback.
  const stop = rest.search(/[/?#]/);
  const hosts = (stop < 0 ? rest : rest.slice(0, stop)).split(',');
  if (!hosts.every((h) => LOOPBACK.test(hostPart(h)))) return false;
  // libpq's host= and hostaddr= parameters override the host in the URL.
  const q = rest.indexOf('?');
  if (q >= 0 && /(?:^|&)(?:host|hostaddr)=/i.test(rest.slice(q + 1))) return false;
  return true;
}

// `group` names the capture group that holds the secret itself (default: the
// whole match). `valid` rejects matches that only look like the pattern.
const DB_URL = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse)(?:\+\w{1,32})?:\/\/[^:\s/@]{0,256}:([^@\s?#]{3,256})@/; // bounded, so it runs in linear time
// A password in the user info of any other URL: https://user:password@host,
// git+https://user:token@host, wss://, ftp://. The password stops at '/', so
// "host:8080/path@x" is a port and a path, not a password. Bounded like DB_URL.
const URL_USERINFO = /\b(?:https?|wss?|ftps?|sftp|ssh|git|svn|smb|ldaps?)(?:\+\w{1,32})?:\/\/[^:\s/@?#]{0,256}:([^@\s/?#]{1,256})@/;
// Passwords that only name what goes there (https://user:password@host), and
// the fixed password GitHub uses when the token is the user name.
const TEMPLATE_PASSWORDS = new Set(['password', 'passwd', 'pass', 'pwd', 'pw', 'secret', 'token', 'apikey', 'api_key', 'api-key', 'key', 'x-oauth-basic']);

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
  { name: 'Password in URL', re: URL_USERINFO, group: 1, valid: (m) => !/^\d+$/.test(m[1]) && !TEMPLATE_PASSWORDS.has(m[1].toLowerCase()) && !isPlaceholder(m[1]) && !isLocalDevDb(m) },
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

export function keyLooksSecret(key) {
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
  // An all-caps word is an acronym (GCP, SA, AWS): short. Longer groups of
  // capitals are what license-style keys are made of (GBRLE-NROXA-FNUYV).
  if (/^[a-z]+\d{0,2}$/.test(t) || /^[A-Z]{1,4}\d{0,2}$/.test(t) || /^\d{1,4}$/.test(t)) return true;
  if (!CAMEL.test(t)) return false;
  const parts = t.replace(/\d+$/, '').split(/(?=[A-Z])/);
  return parts.every((p) => /[aeiouy]/i.test(p)) && parts.length * 3 <= t.length;
}

// Words that environment variable names are made of. A name has at least one
// of them, so groups of random capitals (UPKJSE_QHUSAS) do not count as one.
const ENV_WORDS = new Set([
  'api', 'key', 'keys', 'token', 'tokens', 'secret', 'secrets', 'password', 'passwd', 'pass', 'pwd', 'access', 'auth',
  'pat', 'personal', 'private', 'client', 'id', 'url', 'uri', 'host', 'user', 'username', 'name', 'env', 'var', 'path',
  'service', 'account', 'bearer', 'credential', 'credentials', 'app', 'bot', 'oauth', 'session', 'signing', 'webhook',
  'master', 'admin', 'db', 'database', 'github', 'gitlab', 'openai', 'anthropic', 'aws', 'azure', 'google', 'gcp',
  'slack', 'stripe', 'notion', 'linear', 'jira', 'npm', 'hf', 'mcp', 'prod', 'dev', 'test', 'local', 'config',
  'settings', 'module', 'default', 'file', 'value', 'data', 'home', 'root', 'region', 'project', 'org', 'team',
  'workspace', 'endpoint', 'server', 'ref', 'from',
]);

/**
 * An environment variable name such as GITHUB_PERSONAL_ACCESS_TOKEN: words of
 * capitals (each with at most a two-digit suffix) joined by underscores, one
 * of them a word that such names use.
 */
export function looksLikeEnvName(v) {
  if (!/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) return false;
  const parts = v.split('_');
  return parts.every((p) => /^[A-Z]+\d{0,2}$/.test(p)) && parts.some((p) => ENV_WORDS.has(p.toLowerCase()));
}

// Values that are clearly not credentials, whatever their key is called.
export function looksLikeSetting(v, key) {
  const passKey = /pass|pwd/i.test(key);
  if (/^[a-z][\w+.-]*:\/\//i.test(v)) return true; // any URL; DB URLs are covered by the pattern above
  if (/^[./~]/.test(v) || /^[A-Za-z]:[\\/]/.test(v) || v.startsWith('\\\\')) return true; // paths
  if (/[\\/]/.test(v) && /\.[A-Za-z0-9]{1,5}$/.test(v.split(/[\\/]/).pop())) return true; // relative path to a file
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return true; // email address
  // References to a secret held elsewhere: AWS ARNs, GCP Secret Manager names,
  // Azure Key Vault references. They name the secret; they are not the secret.
  if (/^arn:aws[\w-]*:/i.test(v) || /^projects\/[^/]+\/secrets\//.test(v) || /^@Microsoft\.KeyVault\(/i.test(v)) return true;
  // A passphrase looks like the rules below, so keep them away from password keys.
  if (passKey) return false;
  // An environment variable name (API_KEY=OPENAI_API_KEY).
  if (looksLikeEnvName(v)) return true;
  // Host name: in lower case with a known or two-letter TLD (api.acme.io,
  // login.acme.de), or in any case with a known TLD (Login.MicrosoftOnline.com).
  const host = v.match(/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.([A-Za-z]{2,24})(?::\d{1,5})?(?:\/[^\s]*)?$/);
  if (host) {
    const tld = host[1];
    const lower = !/[A-Z]/.test(v.split('/')[0]);
    if (TLDS.has(tld.toLowerCase()) || (lower && tld.length === 2)) return true;
  }
  // Relative paths: Windows style (keys\id_ed25519) or under a usual folder name.
  if (/^[\w .-]+(?:\\[\w .-]+)+\\?$/.test(v)) return true;
  if (/^(?:secrets?|keys?|credentials?|creds|certs?|config|conf|\.?ssh|private|home|users?|etc|var|opt|data|tmp)[\\/]/i.test(v)) return true;
  // Identifiers, enum values, scope lists and secret ids made of ordinary words:
  // "azure-active-directory", "read:user,repo,gist", "Mail.Read,Files.ReadWrite",
  // "EnvironmentCredential", "prod/mcp/database-credentials".
  if (/^[A-Za-z0-9._:,/\\-]+$/.test(v)) {
    const tokens = v.split(/[._:,/\\-]+/).filter(Boolean);
    // At least one word in lower or mixed case: all-caps groups are a key shape.
    if (tokens.every(wordyToken) && (tokens.length >= 2 || /[a-z][A-Z]/.test(v)) && tokens.some((t) => /[a-z]/.test(t))) return true;
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

// Shannon entropy per character is at most log2(16) = 4 for hex, so random
// hex of 24 or more characters often falls below the cutoff for other
// alphabets. It gets a cutoff that fits its alphabet.
function randomEnough(c) {
  if (c.length >= 24 && /^[0-9a-f]+$/i.test(c)) return /\d/.test(c) && /[a-f]/i.test(c) && entropy(c) >= 2.7;
  return entropy(c) >= 3.2;
}

// A match too simple to count as a secret when the value around it is template text.
// "Password1", "changeme!", "ADMIN2024": one word with a few digits or a symbol after it.
function weakSecret(x) {
  return x.length < 10 || entropy(x) < 3 || /^(?:[A-Z]?[a-z]+|[A-Z]+)\d{0,4}[^A-Za-z0-9]?$/.test(x);
}

const MAX_JSON_DEPTH = 3;
const MAX_JSON_LENGTH = 65536;
const MAX_JSON_STRINGS = 1000;

// The findSecrets() results of every string in a JSON object or array, each
// judged under the key it belongs to, or null when `s` is not one.
function jsonSecrets(s, keyName, depth) {
  const t = s.trim();
  if (t.length < 7 || t.length > MAX_JSON_LENGTH || !((t[0] === '{' && t.endsWith('}')) || (t[0] === '[' && t.endsWith(']')))) return null;
  let doc;
  try { doc = JSON.parse(t); } catch { return null; }
  if (!doc || typeof doc !== 'object') return null;
  const out = [];
  const seen = new Set();
  let budget = MAX_JSON_STRINGS;
  const walk = (v, key, level) => {
    if (budget <= 0 || level > 32) return;
    if (typeof v === 'string' || typeof v === 'number') {
      budget--;
      for (const d of findSecrets(String(v), key, depth + 1)) {
        if (!seen.has(d.secret)) { seen.add(d.secret); out.push(d); }
      }
    } else if (Array.isArray(v)) {
      for (const x of v) walk(x, key, level + 1);
    } else if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) walk(x, k, level + 1);
    }
  };
  walk(doc, keyName, 0);
  return out;
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
export function findSecrets(value, keyName = '', depth = 0) {
  if (value == null) return [];
  const raw = String(value);
  const refs = raw.includes('${') ? parseRefs(raw) : null;
  const s = refs ? refs.text : raw;
  if (!s.trim()) return [];
  // A JSON object or array written into one string ({"apiKey": "..."}): each
  // member is judged under its own key.
  const json = depth < MAX_JSON_DEPTH ? jsonSecrets(s, keyName, depth) : null;
  if (json) return json;
  // A single-word value that is template text as a whole ("your-token-here",
  // ".../sample_mflix") still holds a real secret when the part that a
  // pattern points at is random, so known formats are judged on that part.
  // Only a weak match (a dictionary password) is dropped because of the rest.
  const template = placeholderText(s) && !/\s/.test(s.trim());
  const out = [];
  for (const p of SECRET_PATTERNS) {
    if (p.name === 'Private key') {
      // A private key is the whole value, not just its header line: one
      // finding, judged once (judging the whole value per header line would
      // be quadratic on a value made of repeated headers).
      const m = s.match(p.re);
      if (m && !placeholderText(s)) out.push({ type: p.name, confidence: 'high', match: m[0], secret: s });
      continue;
    }
    for (const m of s.matchAll(globalRe(p.re))) {
      if (p.valid && !p.valid(m)) continue;
      const secret = m[p.group || 0];
      if (placeholderText(secret) || (template && weakSecret(secret))) continue;
      out.push({ type: p.name, confidence: 'high', match: m[0], secret });
    }
  }
  if (out.length) return out;
  if (template) return [];
  // Authorization: Bearer <literal>
  const bearer = s.trim().match(/^(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{16,})$/i);
  if (bearer && !placeholderText(bearer[1])) return [{ type: 'Authorization header credential', confidence: 'high', match: bearer[1], secret: bearer[1] }];
  // Generic: secret-looking key name with a random-looking value. When the value
  // mixes in ${...} references, only a literal default value is judged, so that
  // "${HOME}/.config/x" or "https://${HOST}/api" are not.
  if (!keyLooksSecret(keyName)) return out;
  const candidates = refs ? refs.defaults : [s];
  for (const c of candidates) {
    if (c.length >= 12 && !/\s/.test(c) && randomEnough(c) && !placeholderText(c) && !looksLikeSetting(c, keyName)) {
      out.push({ type: `Credential in ${keyName}`, confidence: 'medium', match: c, secret: c });
    }
  }
  return out;
}

// ---- Arguments ----
// How MCS001 reads one command line argument. This is the only parser for it:
// detection (checks.js) and masking (mask.js) both use it, so whatever is
// reported is also hidden.
const ARG_EQ = /^--?([\w-]+)=(.+)$/; // --api-key=value
const ARG_FLAG = /^--?[\w-]+$/; // --token (its value is the next argument)
const ARG_HEADER = /^([A-Za-z][\w-]*)\s*:\s*(\S.*)$/; // "X-Api-Key: value", "X-Api-Key : value"
const ARG_URL = /^[a-z][a-z0-9+.-]*:\/\//i;
// NAME=value: an environment assignment, bare (env API_KEY=v node ..., or a
// shell script) or as the value of a flag (docker -e API_KEY=v, --env=API_KEY=v).
const ARG_ASSIGN = /^([A-Za-z_][A-Za-z0-9_]{0,127})=(\S.*)$/s;

/**
 * The values MCS001 judges in one argument, each with the key it is judged
 * under and its offset in the argument: first the argument itself (or the part
 * after "--key="), then, when that is a NAME=value assignment, the value under
 * NAME, and when it is a "Name: value" header, the header value.
 * @param {string} arg
 * @param {string} [prev] the argument before it
 * @returns {{key: string, value: string, offset: number}[]}
 */
export function argValues(arg, prev = '') {
  const a = String(arg ?? '');
  const eq = ARG_EQ.exec(a);
  const prevFlag = prev && ARG_FLAG.test(prev) ? prev.replace(/^-+/, '') : '';
  const main = eq ? { key: eq[1], value: eq[2], offset: a.length - eq[2].length } : { key: prevFlag, value: a, offset: 0 };
  const out = [main];
  if (!ARG_URL.test(main.value)) {
    const v = ARG_ASSIGN.exec(main.value);
    if (v) out.push({ key: v[1], value: v[2], offset: main.offset + v[1].length + 1 });
    const h = ARG_HEADER.exec(main.value);
    if (h) out.push({ key: h[1], value: h[2].trim(), offset: main.offset + main.value.length - h[2].length });
  }
  return out;
}

/** The first credential MCS001 reports in one argument, or null. */
export function detectInArg(arg, prev = '') {
  for (const { key, value } of argValues(arg, prev)) {
    const d = detectSecret(value, key);
    if (d) return d;
  }
  return null;
}

/**
 * @param {string} value
 * @param {string} [keyName] the env var / header / arg name the value belongs to
 * @returns {{type: string, confidence: 'high'|'medium', match: string, secret: string}|null}
 */
export function detectSecret(value, keyName = '') {
  return findSecrets(value, keyName)[0] ?? null;
}
