import { RULES } from '../rules.js';
import { displayPath } from '../checks.js';

export function makeColors(enabled) {
  const wrap = (open, close) => (s) => (enabled ? `\x1b[${open}m${s}\x1b[${close}m` : String(s));
  return {
    bold: wrap(1, 22), dim: wrap(2, 22), red: wrap(31, 39), green: wrap(32, 39), yellow: wrap(33, 39),
    blue: wrap(34, 39), magenta: wrap(35, 39), cyan: wrap(36, 39), gray: wrap(90, 39),
    bgRed: wrap('41;97', '49;39'), bgYellow: wrap('43;30', '49;39'), bgGreen: wrap('42;30', '49;39'),
  };
}

const SEV_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };

// Word-wrap plain text so long messages stay readable in narrow terminals.
export function wrap(text, indent, width) {
  const max = Math.max(40, width - indent.length);
  const lines = [];
  let cur = '';
  for (const word of String(text).split(/\s+/)) {
    if (cur && cur.length + 1 + word.length > max) { lines.push(cur); cur = word; } else cur = cur ? `${cur} ${word}` : word;
  }
  if (cur) lines.push(cur);
  return lines.map((l, i) => (i === 0 ? l : indent + l)).join('\n');
}

export function renderTerminal(result, { color = false, verbose = false, width = 100 } = {}) {
  const c = makeColors(color);
  const W = (text, indent) => wrap(text, indent, width);
  const sevColor = { critical: (s) => c.bold(c.red(s)), high: c.red, medium: c.yellow, low: c.blue, info: c.gray };
  const L = [];
  const { score, findings, configs, servers, toolsScanned, liveErrors } = result;

  L.push('');
  L.push(`  ${c.bold('mcpsafe')} ${c.dim('· security audit for MCP servers and AI agent configs')}`);
  L.push('');
  const clients = [...new Set(configs.map((x) => x.source.client))];
  L.push(`  Scanned ${c.bold(configs.length)} config file${configs.length === 1 ? '' : 's'}, ${c.bold(servers)} server${servers === 1 ? '' : 's'}${toolsScanned ? `, ${c.bold(toolsScanned)} tool descriptions` : ''}${clients.length ? c.dim(`  (${clients.join(', ')})`) : ''}`);
  for (const cfg of configs) {
    const n = cfg.servers.length;
    L.push(c.dim(`    ${cfg.error ? c.yellow('!') : '•'} ${displayPath(cfg.source.path)}  ${cfg.error ? cfg.error : `${n} server${n === 1 ? '' : 's'}`}`));
  }
  if (!configs.length) L.push(c.yellow('    No MCP config files found. Pass a file or folder: mcpsafe ./path'));
  L.push('');

  const g = score.grade;
  const badge = g === 'A' || g === 'B' ? c.bgGreen : g === 'C' || g === 'D' ? c.bgYellow : c.bgRed;
  const counts = Object.entries(score.counts).filter(([, n]) => n).map(([s, n]) => sevColor[s](`${n} ${s}`)).join(c.dim(' · '));
  L.push(`  ${c.bold('Score')}  ${badge(` ${score.value}/100  ${g} `)}   ${counts || c.green('no issues found')}`);
  L.push('');

  if (findings.length) {
    L.push(`  ${c.bold('Findings')}`);
    L.push('');
    for (const f of findings) {
      const label = sevColor[f.severity](SEV_LABEL[f.severity].padEnd(8));
      L.push(`  ${label}  ${c.dim(f.id)}  ${c.bold(f.title)}`);
      const where = [f.server ? `server ${c.cyan(`"${f.server}"`)}` : null, f.client, displayPath(f.file)].filter(Boolean).join(c.dim(' · '));
      L.push(`            ${where}`);
      L.push(`            ${W(f.message, ' '.repeat(12))}`);
      if (f.evidence && verbose) L.push(c.dim(`            ↳ ${f.evidence}`));
      L.push('');
    }

    L.push(`  ${c.bold('Fix list')} ${c.dim('(highest impact first)')}`);
    L.push('');
    const byRule = new Map();
    for (const f of findings) {
      if (!byRule.has(f.id)) byRule.set(f.id, new Set());
      byRule.get(f.id).add(f.server || displayPath(f.file));
    }
    let i = 1;
    for (const [id, targets] of byRule) {
      const list = [...targets];
      L.push(`  ${c.bold(`${i++}.`)} ${RULES[id].title} ${c.dim(`(${list.slice(0, 4).join(', ')}${list.length > 4 ? `, +${list.length - 4} more` : ''})`)}`);
      L.push(`     ${c.green('→')} ${W(RULES[id].fix, ' '.repeat(7))}`);
    }
    L.push('');
  }

  if (findings.length) {
    L.push(`  ${c.bold('Result')}  ${badge(` ${score.value}/100  ${g} `)}   ${findings.length} finding${findings.length === 1 ? '' : 's'} across ${new Set(findings.map((f) => f.server).filter(Boolean)).size} server(s). Fix the top items first.`);
    L.push('');
  }
  if (liveErrors?.length) {
    L.push(c.dim(`  Could not list tools for: ${liveErrors.map((e) => `${e.server} (${e.error})`).join(', ')}`));
    L.push('');
  }
  if (!result.live && !toolsScanned && servers > 0) {
    L.push(c.dim(`  ${W('Tip: run with --connect to also check tool descriptions for hidden instructions (this starts your servers).', '  ')}`));
    L.push('');
  }
  return L.join('\n');
}
