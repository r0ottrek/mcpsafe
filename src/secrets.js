// Detects credentials pasted directly into config values.

export const SECRET_PATTERNS = [
  { name: 'Anthropic API key', re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI API key', re: /sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/ },
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
  { name: 'Database URL with password', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/@]+:[^@\s/]{3,}@/ },
];

const SECRET_KEY_NAME = /(api[_-]?key|apikey|token|secret|passw(or)?d|passwd|pwd|credential|auth|private[_-]?key|access[_-]?key|client[_-]?secret|bearer|\bpat\b|_pat$)/i;

export function isPlaceholder(v) {
  const s = String(v).trim();
  if (!s) return true;
  if (/\$\{[^}]+\}/.test(s)) return true; // ${VAR}, ${env:VAR}, ${input:id}
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
  if (s.length <= 8) return '****';
  return `${s.slice(0, 4)}…${'*'.repeat(4)} (${s.length} chars)`;
}

/**
 * @param {string} value
 * @param {string} [keyName] the env var / header / arg name the value belongs to
 * @returns {{type: string, confidence: 'high'|'medium', match: string}|null}
 */
export function detectSecret(value, keyName = '') {
  if (value == null) return null;
  const s = String(value);
  if (isPlaceholder(s)) return null;
  for (const p of SECRET_PATTERNS) {
    const m = s.match(p.re);
    if (m) return { type: p.name, confidence: 'high', match: m[0] };
  }
  // Authorization: Bearer <literal>
  const bearer = s.match(/^(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{16,})$/i);
  if (bearer && !isPlaceholder(bearer[1])) return { type: 'Authorization header credential', confidence: 'high', match: bearer[1] };
  // Generic: secret-looking key name with a random-looking value
  if (keyName && SECRET_KEY_NAME.test(keyName) && s.length >= 12 && !/\s/.test(s) && !/^https?:\/\//.test(s) && !/^[./~]/.test(s) && entropy(s) >= 3.2) {
    return { type: `Credential in ${keyName}`, confidence: 'medium', match: s };
  }
  return null;
}
