// SARIF 2.1.0 output, so findings show up in GitHub code scanning.
import path from 'node:path';
import { RULES } from '../rules.js';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };

export function renderSarif(result, { root = process.cwd() } = {}) {
  const rules = Object.entries(RULES).map(([id, r]) => ({
    id,
    name: r.title.replace(/[^A-Za-z0-9]+/g, ' ').trim().split(' ').map((w) => w[0].toUpperCase() + w.slice(1)).join(''),
    shortDescription: { text: r.title },
    fullDescription: { text: r.why },
    help: { text: r.fix, markdown: `**Why:** ${r.why}\n\n**Fix:** ${r.fix}` },
    properties: { tags: ['security', 'mcp'], 'security-severity': SECURITY_SEVERITY[r.severity] },
  }));

  const lineOf = (file, jsonPath, text) => {
    if (!text || !jsonPath) return 1;
    // Find the line of the most specific key in the JSON path.
    const keys = jsonPath.match(/[\w.@-]+|"[^"]+"/g) || [];
    let idx = 0;
    for (const k of keys) {
      const key = k.replace(/^"|"$/g, '').replace(/\[\d+\]$/, '');
      const at = text.indexOf(`"${key}"`, idx);
      if (at >= 0) idx = at;
    }
    return text.slice(0, idx).split('\n').length;
  };

  const results = result.findings.map((f) => {
    const cfg = result.configs.find((c) => c.source.path === f.file);
    const rel = f.file ? path.relative(root, f.file).replace(/\\/g, '/') : 'unknown';
    return {
      ruleId: f.id,
      level: LEVEL[f.severity],
      message: { text: `${f.server ? `[${f.server}] ` : ''}${f.message}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: rel }, region: { startLine: lineOf(f.file, f.jsonPath, cfg?.text) } } }],
      properties: { 'security-severity': SECURITY_SEVERITY[f.severity], severity: f.severity },
    };
  });

  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'mcpsafe', version: result.version, informationUri: 'https://github.com/r0ottrek/mcpsafe', rules } }, results }],
  }, null, 2);
}
