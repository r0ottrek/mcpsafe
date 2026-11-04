// Markdown summary, used for GitHub Actions job summaries and PR comments.
import path from 'node:path';
import { RULES, SEVERITIES } from '../rules.js';
import { impactByRule } from '../score.js';
import { safe, unreadSummary } from './text.js';

const VERDICT = { A: 'Looks good', B: 'Minor issues', C: 'Needs attention', D: 'At risk', F: 'High risk' };
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
// "a, b and c"
const list = (items) => (items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`);

// Text from configs and servers (server names, package names, paths) is shown
// as literal text. It cannot add HTML, links or images to the summary, close
// a code span, or end a table row: control characters are made visible
// (safe), & < > become entities, and Markdown punctuation is escaped.
const cell = (s) => safe(s)
  .replace(/[&<>]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[ch]))
  .replace(/[\\`*_[\]()!~|#]/g, '\\$&');

// A code span that holds any text: the fence is longer than any run of
// backticks inside, and the spaces inside it are removed again when rendered.
// A pipe still needs a backslash inside a code span in a GFM table.
const code = (s) => {
  const v = safe(s).replace(/\|/g, '\\|');
  const fence = '`'.repeat(Math.max(0, ...(v.match(/`+/g) || []).map((r) => r.length)) + 1);
  return `${fence} ${v} ${fence}`;
};

export function renderMarkdown(result, { root = process.cwd() } = {}) {
  const { score, findings, configs, servers, toolsScanned } = result;
  const errors = result.errors ?? configs.filter((c) => c.error).map((c) => ({ path: c.source.path, error: c.error }));
  const L = [];
  const rel = (p) => (p ? path.relative(root, p).replace(/\\/g, '/') || '.' : '');
  if (!configs.length && !toolsScanned && errors.length) {
    // Nothing was read, so there is no score to show: a grade here would read as a pass.
    const missing = errors.filter((e) => e.missing);
    L.push('### mcpsafe: nothing was scanned');
    L.push('');
    if (missing.length) L.push(`Path not found: ${missing.map((e) => code(rel(e.path))).join(', ')}.`);
    for (const e of errors.filter((x) => !x.missing)) L.push(`Could not read ${code(rel(e.path))}: ${cell(e.error)}.`);
    return `${L.join('\n')}\n`;
  }
  L.push(`### mcpsafe: ${score.value}/100, grade ${score.grade}`);
  L.push('');
  const scanned = configs.length || !toolsScanned
    ? `Scanned ${list([plural(configs.length, 'config file'), plural(servers, 'MCP server'), ...(toolsScanned ? [plural(toolsScanned, 'tool description')] : [])])}.`
    : `No config files scanned. Checked ${plural(toolsScanned, 'tool description')} from a tools file.`;
  L.push(`${errors.length ? 'Incomplete' : VERDICT[score.grade]}. ${scanned}`);
  L.push('');
  if (errors.length) {
    L.push(`> **Incomplete scan:** ${unreadSummary(errors)}, so the score covers only the files that were read.`);
    L.push('');
  }
  if (!findings.length) {
    L.push(errors.length ? 'No findings in the files that were read.' : 'No findings.');
    return `${L.join('\n')}\n`;
  }
  L.push(SEVERITIES.filter((s) => score.counts[s]).map((s) => `${score.counts[s]} ${s}`).join(', ') + '.');
  L.push('');
  L.push('| Severity | Finding | Server | Location |');
  L.push('|---|---|---|---|');
  for (const f of findings) {
    const where = f.file ? path.relative(root, f.file).replace(/\\/g, '/') : '';
    L.push(`| ${f.severity} | **${cell(f.title)}** <sub>${f.id}</sub><br>${cell(f.message)} | ${f.server ? code(f.server) : ''} | ${where ? code(`${where}${f.line ? `:${f.line}` : ''}`) : ''} |`);
  }
  L.push('');
  const impact = impactByRule(findings);
  const ids = [...new Set(findings.map((f) => f.id))];
  L.push('<details><summary>How to fix</summary>');
  L.push('');
  for (const id of ids) L.push(`- **${RULES[id].title}**${impact[id] > 0 ? ` (+${plural(impact[id], 'point')})` : ''}: ${RULES[id].fix}`);
  L.push('');
  L.push('</details>');
  return `${L.join('\n')}\n`;
}
