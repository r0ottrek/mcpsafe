// Markdown summary, used for GitHub Actions job summaries and PR comments.
import path from 'node:path';
import { RULES, SEVERITIES } from '../rules.js';
import { impactByRule } from '../score.js';

const VERDICT = { A: 'Looks good', B: 'Minor issues', C: 'Needs attention', D: 'At risk', F: 'High risk' };
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function renderMarkdown(result, { root = process.cwd() } = {}) {
  const { score, findings, configs, servers } = result;
  const L = [];
  L.push(`### mcpsafe: ${score.value}/100, grade ${score.grade}`);
  L.push('');
  L.push(`${VERDICT[score.grade]}. Scanned ${configs.length} config file${configs.length === 1 ? '' : 's'} and ${servers} MCP server${servers === 1 ? '' : 's'}.`);
  L.push('');
  if (!findings.length) {
    L.push('No findings.');
    return `${L.join('\n')}\n`;
  }
  L.push(SEVERITIES.filter((s) => score.counts[s]).map((s) => `${score.counts[s]} ${s}`).join(', ') + '.');
  L.push('');
  L.push('| Severity | Finding | Server | Location |');
  L.push('|---|---|---|---|');
  for (const f of findings) {
    const rel = f.file ? path.relative(root, f.file).replace(/\\/g, '/') : '';
    L.push(`| ${f.severity} | **${cell(f.title)}** <sub>${f.id}</sub><br>${cell(f.message)} | ${f.server ? `\`${cell(f.server)}\`` : ''} | \`${cell(rel)}${f.line ? `:${f.line}` : ''}\` |`);
  }
  L.push('');
  const impact = impactByRule(findings);
  const ids = [...new Set(findings.map((f) => f.id))];
  L.push('<details><summary>How to fix</summary>');
  L.push('');
  for (const id of ids) L.push(`- **${RULES[id].title}**${impact[id] > 0 ? ` (+${impact[id]} points)` : ''}: ${RULES[id].fix}`);
  L.push('');
  L.push('</details>');
  return `${L.join('\n')}\n`;
}
