// Detects credentials pasted directly into config values.

// `group` names the capture group that holds the secret itself (default: the
// whole match). `valid` rejects matches that only look like the pattern.
const DB_URL = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse)(?:\+\w{1,32})?:\/\/[^:\s/@]{0,256}:([^@\s?#]{3,256})@/; // bounded, so it runs in linear time

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
  { name: 'Database URL with password', re: DB_URL, group: 1, valid: (m) => !/^\d+(?:\/|$)/.test(m[1]) && !isPlaceholder(m[1]) },
];

const SECRET_KEY_NAME = /(api[_-]?key|apikey|token(?!iz)|secret|passw(or)?d|passwd|pwd|passphrase|credential|private[_-]?key|access[_-]?key|bearer)/i;
// Whole words only, so OAUTH, AUTHOR and AUTH0 do not count.
const SECRET_KEY_WORDS = new Set(['auth', 'authorization', 'pat']);
// Key names whose last word says the value is a setting, not the secret itself
// (TOKEN_URL, AUTH_PROVIDER, SECRET_ID, GOOGLE_APPLICATION_CREDENTIALS_PATH, ...).
const NON_SECRET_KEY_END = new Set([
  'path', 'file', 'filename', 'dir', 'directory', 'folder', 'url', 'uri', 'endpoint', 'domain', 'host', 'hostname', 'port',
  'scope', 'scopes', 'provider', 'method', 'mode', 'type', 'email', 'name', 'id', 'user', 'username', 'region', 'issuer',
  'audience', 'enabled', 'limit', 'ttl', 'expiry', 'version', 'format', 'size', 'count',
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

// Values that are clearly not credentials, whatever their key is called.
export function looksLikeSetting(v, key) {
  if (/^[a-z][\w+.-]*:\/\//i.test(v)) return true; // any URL; DB URLs are covered by the pattern above
  if (/^[./~]/.test(v) || /^[A-Za-z]:[\\/]/.test(v) || v.startsWith('\\\\')) return true; // paths
  if (/[\\/]/.test(v) && /\.[A-Za-z0-9]{1,5}$/.test(v.split(/[\\/]/).pop())) return true; // relative path to a file
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return true; // email address
  if (/^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?::\d+)?(?:\/\S*)?$/.test(v)) return true; // host name
  // Lowercase words joined by - _ . : , or / (scopes, provider names, AWS secret ids).
  // A passphrase looks the same, so keep these for password keys.
  if (!/pass|pwd/i.test(key) && /^[a-z]+\d*(?:[-_.:,/][a-z]+\d*)+$/.test(v)) return true;
  return false;
}

const REF = /\$\{[^}]*\}/g;
const REF_DEFAULT = /\$\{[A-Za-z_]\w*:?-([^}]*)\}/g; // ${VAR:-default} and ${VAR-default}

// Replace variable references by their default value (or nothing), so that a
// literal committed next to a reference is still checked.
export function expandRefs(s) {
  return String(s).replace(REF_DEFAULT, '$1').replace(REF, '');
}

export function isPlaceholder(v) {
  let s = String(v).trim();
  if (!s) return true;
  // ${VAR}, ${env:VAR}, ${input:id}: a placeholder only if nothing literal is left
  if (/\$\{[^}]*\}/.test(s)) { s = expandRefs(s).trim(); if (!s) return true; }
  if (/^\$[A-Za-z_]\w*$/.test(s)) return true; // $VAR
  if (/^%[A-Za-z_]\w*%$/.test(s)) return true; // %VAR%
  if (/^<.*>$/.test(s)) return true;
  if (/^(your|my|insert|replace|enter|put|add)[\s_-]/i.test(s)) return true;
  if (/(placeholder|changeme|example|dummy|redacted|xxxx|\*\*\*\*|here$)/i.test(s)) return true;
  if (/^(true|false|null|none|\d+)$/i.test(s)) return true;
  return false;
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
  const hasRef = /\$\{[^}]*\}/.test(raw);
  const s = hasRef ? expandRefs(raw) : raw;
  if (isPlaceholder(s)) return [];
  const out = [];
  for (const p of SECRET_PATTERNS) {
    for (const m of s.matchAll(globalRe(p.re))) {
      if (p.valid && !p.valid(m)) continue;
      // A private key is the whole value, not just its header line.
      const secret = p.name === 'Private key' ? s : m[p.group || 0];
      out.push({ type: p.name, confidence: 'high', match: m[0], secret });
    }
  }
  if (out.length) return out;
  // Authorization: Bearer <literal>
  const bearer = s.trim().match(/^(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{16,})$/i);
  if (bearer && !isPlaceholder(bearer[1])) return [{ type: 'Authorization header credential', confidence: 'high', match: bearer[1], secret: bearer[1] }];
  // Generic: secret-looking key name with a random-looking value. When the value
  // mixes in ${...} references, only a literal default value is judged, so that
  // "${HOME}/.config/x" or "https://${HOST}/api" are not.
  if (!keyLooksSecret(keyName)) return out;
  const candidates = hasRef ? [...raw.matchAll(REF_DEFAULT)].map((m) => m[1]) : [s];
  for (const c of candidates) {
    if (c.length >= 12 && !/\s/.test(c) && !isPlaceholder(c) && !looksLikeSetting(c, keyName) && entropy(c) >= 3.2) {
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
