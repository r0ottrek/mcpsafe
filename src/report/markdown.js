// Markdown summary, used for GitHub Actions job summaries and PR comments.
import path from 'node:path';
import { RULES } from '../rules.js';

const ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function renderMarkdown(result, { root = process.cwd() } = {}) {
  const { score, findings, configs, servers } = result;
  const L = [];
  L.push(`### mcpsafe: ${score.value}/100 (grade ${score.grade})`);
  L.push('');
  const counts = Object.entries(score.counts).filter(([, n]) => n).map(([s, n]) => `${ICON[s]} ${n} ${s}`).join(' · ');
  L.push(`Scanned ${configs.length} config file${configs.length === 1 ? '' : 's'} and ${servers} server${servers === 1 ? '' : 's'}. ${counts || '✅ No issues found.'}`);
  if (!findings.length) return `${L.join('\n')}\n`;
  L.push('');
  L.push('| Severity | Rule | Server | File | Finding |');
  L.push('|---|---|---|---|---|');
  for (const f of findings) {
    const rel = f.file ? path.relative(root, f.file).replace(/\\/g, '/') : '';
    L.push(`| ${ICON[f.severity]} ${f.severity} | ${f.id} ${cell(f.title)} | ${cell(f.server || '')} | \`${cell(rel)}\` | ${cell(f.message)} |`);
  }
  L.push('');
  L.push('<details><summary>How to fix</summary>');
  L.push('');
  for (const id of [...new Set(findings.map((f) => f.id))]) L.push(`- **${id} ${RULES[id].title}:** ${RULES[id].fix}`);
  L.push('');
  L.push('</details>');
  return `${L.join('\n')}\n`;
}
