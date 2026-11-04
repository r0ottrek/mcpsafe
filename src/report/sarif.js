// SARIF 2.1.0 output, so findings show up in GitHub code scanning.
import path from 'node:path';
import { RULES } from '../rules.js';
import { lineOf } from '../locate.js';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };

const cap = (s) => s[0].toUpperCase() + s.slice(1);
const ruleName = (title) => title.replace(/[^A-Za-z0-9]+/g, ' ').trim().split(' ').map((w) => w[0].toUpperCase() + w.slice(1)).join('');

// GitHub code scanning takes an alert's severity from the rule, not from the
// result. A finding whose severity differs from its rule's default (a secret
// in a project file is critical, an inline shell launcher is low, a disabled
// server is one step lower) therefore gets a rule of its own, named after the
// rule and the severity, for example MCS001-critical. Findings at the default
// severity keep the plain rule id.
const ruleIdOf = (f) => (f.severity === RULES[f.id].severity ? f.id : `${f.id}-${f.severity}`);

function descriptor(id, base, severity) {
  const r = RULES[base];
  return {
    id,
    name: ruleName(r.title) + (id === base ? '' : cap(severity)),
    shortDescription: { text: r.title },
    fullDescription: { text: r.why },
    help: { text: r.fix, markdown: `**Why:** ${r.why}\n\n**Fix:** ${r.fix}` },
    defaultConfiguration: { level: LEVEL[severity] },
    properties: { tags: ['security', 'mcp'], 'security-severity': SECURITY_SEVERITY[severity], severity, ...(id === base ? {} : { baseRuleId: base }) },
  };
}

// A relative URI reference for a file, with each path segment percent-encoded.
// A path on another drive cannot be made relative and becomes a file: URI.
function uriOf(file, root) {
  if (!file) return 'unknown';
  const rel = path.relative(root, file);
  const abs = path.isAbsolute(rel) || /^[A-Za-z]:/.test(rel);
  const parts = rel.split(/[\\/]/).map((p, i) => (abs && i === 0 && /^[A-Za-z]:$/.test(p) ? p : encodeURIComponent(p)));
  return abs ? `file:///${parts.join('/').replace(/^\/+/, '')}` : parts.join('/');
}

export function renderSarif(result, { root = process.cwd() } = {}) {
  const rules = Object.entries(RULES).map(([id, r]) => descriptor(id, id, r.severity));
  const index = new Map(rules.map((r, i) => [r.id, i]));
  for (const f of result.findings) {
    const id = ruleIdOf(f);
    if (!index.has(id)) { index.set(id, rules.length); rules.push(descriptor(id, f.id, f.severity)); }
  }

  const results = result.findings.map((f) => {
    const cfg = result.configs.find((c) => c.source.path === f.file);
    const id = ruleIdOf(f);
    // The line the scan found (it falls back to the server's line), else
    // look it up again, else the top of the file.
    const line = f.line || lineOf(cfg?.text, f.jsonPath) || lineOf(cfg?.text, f.serverPath) || 1;
    return {
      ruleId: id,
      ruleIndex: index.get(id),
      level: LEVEL[f.severity],
      message: { text: `${f.server ? `[${f.server}] ` : ''}${f.message}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: uriOf(f.file, root) }, region: { startLine: line } } }],
      properties: { 'security-severity': SECURITY_SEVERITY[f.severity], severity: f.severity },
    };
  });

  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'mcpsafe', version: result.version, informationUri: 'https://github.com/r0ottrek/mcpsafe', rules } }, results }],
  }, null, 2);
}
