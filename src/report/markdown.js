// Markdown summary, used for GitHub Actions job summaries and PR comments.
import path from 'node:path';
import { RULES, SEVERITIES } from '../rules.js';
import { impactByRule } from '../score.js';

const ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
const VERDICT = { A: 'Looks good', B: 'Minor issues', C: 'Needs attention', D: 'At risk', F: 'High risk' };
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function renderMarkdown(result, { root = process.cwd() } = {}) {
  const { score, findings, configs, servers } = result;
  const L = [];
  const bar = '█'.repeat(Math.round(score.value / 5)) + '░'.repeat(20 - Math.round(score.value / 5));
  L.push(`## mcpsafe · ${score.value}/100 · grade ${score.grade}`);
  L.push('');
  L.push(`\`${bar}\` **${VERDICT[score.grade]}.** Scanned ${configs.length} config file${configs.length === 1 ? '' : 's'} and ${servers} MCP server${servers === 1 ? '' : 's'}.`);
  L.push('');
  if (!findings.length) {
    L.push('✅ No issues found.');
    return `${L.join('\n')}\n`;
  }
  const sevs = SEVERITIES.filter((s) => s !== 'info' || score.counts.info);
  L.push(`| ${sevs.map((s) => `${ICON[s]} ${s[0].toUpperCase()}${s.slice(1)}`).join(' | ')} |`);
  L.push(`|${sevs.map(() => ':---:').join('|')}|`);
  L.push(`| ${sevs.map((s) => (score.counts[s] ? `**${score.counts[s]}**` : '0')).join(' | ')} |`);
  L.push('');
  L.push('| | Finding | Server | Location |');
  L.push('|---|---|---|---|');
  for (const f of findings) {
    const rel = f.file ? path.relative(root, f.file).replace(/\\/g, '/') : '';
    L.push(`| ${ICON[f.severity]} | **${cell(f.title)}** <sub>${f.id}</sub><br>${cell(f.message)} | ${f.server ? `\`${cell(f.server)}\`` : ''} | \`${cell(rel)}${f.line ? `:${f.line}` : ''}\` |`);
  }
  L.push('');
  const impact = impactByRule(findings);
  const ids = [...new Set(findings.map((f) => f.id))];
  L.push('<details><summary><b>How to fix</b></summary>');
  L.push('');
  for (const id of ids) L.push(`- **${RULES[id].title}**${impact[id] > 0 ? ` (+${impact[id]} pts)` : ''}: ${RULES[id].fix}`);
  L.push('');
  L.push('</details>');
  return `${L.join('\n')}\n`;
}
