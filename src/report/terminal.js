// Terminal output. The default view is a summary: logo, score, severity
// chart, findings grouped by server and the fixes ranked by score gain.
// --verbose adds compiler-style diagnostics that point at the exact config
// line of every finding.
import { RULES, SEVERITIES } from '../rules.js';
import { displayPath, POISON } from '../checks.js';
import { impactByRule } from '../score.js';
import { snippet } from '../locate.js';

export function makeColors(enabled) {
  const wrap = (open, close) => (s) => (enabled ? `\x1b[${open}m${s}\x1b[${close}m` : String(s));
  return {
    bold: wrap(1, 22), dim: wrap(2, 22), red: wrap(31, 39), green: wrap(32, 39), yellow: wrap(33, 39),
    blue: wrap(34, 39), magenta: wrap(35, 39), cyan: wrap(36, 39), gray: wrap(90, 39),
  };
}

// eslint-disable-next-line no-control-regex
const visible = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, '').length;

export function wrap(text, indent, width) {
  const max = Math.max(30, width - indent.length);
  const lines = [];
  let cur = '';
  for (const word of String(text).split(/\s+/)) {
    if (cur && cur.length + 1 + word.length > max) { lines.push(cur); cur = word; } else cur = cur ? `${cur} ${word}` : word;
  }
  if (cur) lines.push(cur);
  return lines;
}

// Where on the line to put the ^^^ underline: the last key of the JSON path.
function underline(text, jsonPath) {
  const start = text.search(/\S/);
  if (start < 0) return null;
  const key = (jsonPath || '').match(/"[^"]+"|[^.[\]"]+/g)?.filter((k) => !/^\d+$/.test(k)).pop()?.replace(/"/g, '');
  const at = key ? text.indexOf(`"${key}"`) : -1;
  const end = text.replace(/[,{[\s]+$/, '').length;
  if (at >= 0 && !/\[\d+\]$/.test(jsonPath)) return [at, Math.max(at + key.length + 2, end) - at];
  return [start, Math.max(1, end - start)];
}

function renderDiagnostics(result, { color = false, width = 100 } = {}) {
  const c = makeColors(color);
  const W = Math.min(Math.max(width, 60), 100);
  const sev = { critical: (s) => c.bold(c.red(s)), high: (s) => c.bold(c.red(s)), medium: (s) => c.bold(c.yellow(s)), low: (s) => c.bold(c.blue(s)), info: (s) => c.bold(c.gray(s)) };
  const gut = (s) => c.blue(s);
  const { findings, configs } = result;
  const textOf = Object.fromEntries(configs.map((x) => [x.source.path, x.text]));
  const L = [];
  const push = (s = '') => L.push(s);
  const gutterW = Math.max(1, ...findings.map((f) => String(f.line || '').length));
  const note = (label, text, pad) => {
    for (const [i, line] of wrap(text, '', W - pad.length - label.length - 6).entries()) push(i ? `${pad}   ${' '.repeat(label.length + 2)}${line}` : `${pad} ${gut('=')} ${c.bold(`${label}:`)} ${line}`);
  };
  for (const f of findings) {
    push(`${sev[f.severity](`${f.severity}[${f.id}]`)}${c.bold(`: ${f.title}`)}`);
    // Masked with the whole file as context, so a value after a --flag line is hidden too.
    const src = f.line ? snippet(textOf[f.file], f.line, 0)?.[0]?.text ?? null : null;
    const num = f.line ? String(f.line).padStart(gutterW) : '';
    const pad = ' '.repeat(gutterW);
    if (f.file) push(`${pad}${gut('-->')} ${displayPath(f.file)}${f.line ? `:${f.line}` : ''}`);
    if (src != null && src.trim()) {
      const [col, len] = underline(src, f.jsonPath) || [0, 1];
      const shown = src.length > W - pad.length - 4 ? `${src.slice(0, W - pad.length - 5)}…` : src;
      const carets = '^'.repeat(Math.max(1, Math.min(len, shown.length - col)));
      push(`${pad} ${gut('|')}`);
      push(`${gut(num)} ${gut('|')} ${shown}`);
      const label = f.message.length + col + carets.length + 1 < W - pad.length - 4 ? ` ${f.message}` : '';
      push(`${pad} ${gut('|')} ${' '.repeat(col)}${sev[f.severity](carets)}${label ? sev[f.severity](label) : ''}`);
      if (!label) note('note', f.message, pad);
    } else {
      push(`${pad} ${gut('|')}`);
      note('note', f.message, pad);
    }
    if (f.id === 'MCS016' && f.evidence) {
      const found = [];
      for (const [re] of POISON) { const m = f.evidence.match(re); if (m && m[0].trim()) found.push(`"${m[0].replace(/\s+/g, ' ').trim()}"`); }
      if (found.length) note('found', [...new Set(found)].slice(0, 4).join(', '), pad);
    }
    if (f.server) note('server', `${f.server}${f.client ? ` (${f.client})` : ''}`, pad);
    note('fix', f.fix, pad);
    push();
  }

  return L;
}

// ---------------------------------------------------------------------------
// Overview

// Three-row box-drawing glyphs (in the style of figlet's "future" font).
const GLYPHS = {
  m: ['┏┳┓', '┃┃┃', '╹ ╹'], c: ['┏━╸', '┃  ', '┗━╸'], p: ['┏━┓', '┣━┛', '╹  '], s: ['┏━┓', '┗━┓', '┗━┛'],
  a: ['┏━┓', '┣━┫', '╹ ╹'], f: ['┏━╸', '┣╸ ', '╹  '], e: ['┏━╸', '┣╸ ', '┗━╸'], b: ['┏┓ ', '┣┻┓', '┗━┛'], d: ['╺┳┓', ' ┃┃', '╺┻┛'],
  0: ['┏━┓', '┃┃┃', '┗━┛'], 1: ['╺┓ ', ' ┃ ', '╺┻╸'], 2: ['┏━┓', '┏━┛', '┗━╸'], 3: ['┏━┓', '╺━┫', '┗━┛'], 4: ['╻ ╻', '┗━┫', '  ╹'],
  5: ['┏━╸', '┗━┓', '┗━┛'], 6: ['┏━┓', '┣━┓', '┗━┛'], 7: ['┏━┓', '  ┃', '  ╹'], 8: ['┏━┓', '┣━┫', '┗━┛'], 9: ['┏━┓', '┗━┫', '┗━┛'],
};
export const big = (text) => [0, 1, 2].map((row) => [...String(text).toLowerCase()].map((ch) => GLYPHS[ch]?.[row] ?? '   ').join(''));

const VERDICT = { A: 'looks good', B: 'minor issues', C: 'needs attention', D: 'at risk', F: 'high risk' };
const SEV_SHORT = { critical: 'CRIT', high: 'HIGH', medium: 'MED ', low: 'LOW ', info: 'INFO' };

function shortPath(p, max = 52) {
  const d = displayPath(p) || '';
  if (d.length <= max) return d;
  const parts = d.split(/[\\/]/);
  const last = parts.pop();
  let head = parts.shift();
  while (parts.length && `${head}/${parts[0]}/…/${last}`.length <= max) head = `${head}/${parts.shift()}`;
  return `${head}/…/${last}`;
}

export function renderTerminal(result, { color = false, verbose = false, width = 100 } = {}) {
  const c = makeColors(color);
  const W = Math.min(Math.max(width, 64), 96);
  const { score, findings, configs, servers, toolsScanned, liveErrors } = result;
  const g = score.grade;
  const tone = g === 'A' || g === 'B' ? c.green : g === 'C' || g === 'D' ? c.yellow : c.red;
  const sevC = { critical: (s) => c.bold(c.red(s)), high: c.red, medium: c.yellow, low: c.blue, info: c.gray };
  const L = [];
  const push = (s = '') => L.push(s);
  const head = (t, right = '') => { push(`  ${c.bold(t)}${right ? `${' '.repeat(Math.max(2, W - 4 - t.length - visible(right)))}${right}` : ''}`); push(`  ${c.dim('─'.repeat(W - 4))}`); };

  // Logo
  const clients = [...new Set(configs.map((x) => x.source.client))];
  const logo = big('mcpsafe');
  const side = [
    c.dim(`v${result.version}`),
    'security audit for MCP servers',
    c.dim(`${configs.length} file${configs.length === 1 ? '' : 's'} · ${servers} server${servers === 1 ? '' : 's'}${toolsScanned ? ` · ${toolsScanned} tools` : ''}`),
  ];
  push();
  logo.forEach((row, i) => push(`  ${c.cyan(c.bold(row))}   ${side[i]}`));
  push();

  if (!configs.length) {
    push(`  ${c.yellow('No MCP config files found.')} Pass a file or folder: mcpsafe ./path`);
    push();
    return L.join('\n');
  }

  // Score: big digits, grade, bar
  const digits = big(score.value);
  const grade = big(g);
  const barW = Math.min(50, W - 4 - 22);
  const bands = Array(barW).fill(' ');
  for (const [ch, at] of [['F', 0.3], ['D', 0.65], ['C', 0.75], ['B', 0.85], ['A', 0.95]]) bands[Math.min(barW - 1, Math.floor(at * barW))] = ch;
  const filled = Math.round((score.value / 100) * barW);
  const bar = tone('█'.repeat(filled)) + c.dim('░'.repeat(barW - filled));
  const right = [
    `${c.bold('score')} ${tone(c.bold(score.value))}${c.dim('/100')}   ${c.bold('grade')} ${tone(c.bold(g))}   ${tone(VERDICT[g])}`,
    bar,
    bands.map((ch) => (ch === g ? tone(c.bold(ch)) : c.dim(ch))).join(''),
  ];
  const digW = Math.max(9, digits[0].length);
  for (let i = 0; i < 3; i++) push(`  ${tone(c.bold(digits[i].padEnd(digW)))} ${tone(grade[i])}   ${right[i]}`);
  push();

  if (!findings.length) {
    push(`  ${c.green('✔')} ${c.bold('No findings.')} ${c.dim(`${servers} server${servers === 1 ? '' : 's'} checked against ${Object.keys(RULES).length} rules${clients.length ? ` in ${clients.join(', ')}` : ''}.`)}`);
    push();
  } else {
    // Severity chart
    const maxN = Math.max(...SEVERITIES.map((s) => score.counts[s]));
    const chartW = 24;
    for (const s of SEVERITIES.filter((x) => x !== 'info' || score.counts.info)) {
      const n = score.counts[s];
      const len = n ? Math.max(1, Math.round((n / maxN) * chartW)) : 0;
      push(`  ${(n ? sevC[s] : c.dim)(s.padEnd(9))} ${(n ? c.bold : c.dim)(String(n).padStart(2))}  ${sevC[s]('■'.repeat(len))}`);
    }
    push();

    if (verbose) {
      head('Findings');
      push();
      for (const line of renderDiagnostics(result, { color, width: W })) push(line ? `  ${line}` : '');
    } else {
      // Findings as a tree, grouped by server
      head('Findings', c.dim('-v for config excerpts'));
      push();
      const groups = new Map();
      for (const f of findings) {
        const key = `${f.server ?? ''}\0${f.file}`;
        if (!groups.has(key)) groups.set(key, { f, items: [] });
        groups.get(key).items.push(f);
      }
      for (const { f: first, items } of groups.values()) {
        const name = first.server || shortPath(first.file).split('/').pop();
        push(`  ${sevC[items[0].severity]('●')} ${c.bold(name)}  ${c.dim(`${first.client ? `${first.client} · ` : ''}${shortPath(first.file)}`)}`);
        items.forEach((f, i) => {
          const last = i === items.length - 1;
          const branch = c.dim(last ? '└─' : '├─');
          const stem = c.dim(last ? '  ' : '│ ');
          const line = f.line ? c.dim(`:${f.line}`) : '';
          const title = `${sevC[f.severity](SEV_SHORT[f.severity])}  ${f.title}`;
          push(`  ${branch} ${title}${' '.repeat(Math.max(2, W - 7 - visible(title) - visible(line)))}${line}`);
          for (const m of wrap(f.message, '', W - 16)) push(`  ${stem}       ${c.dim(m)}`);
        });
        push();
      }
    }

    // Fix first
    const impact = impactByRule(findings);
    const byRule = new Map();
    for (const f of findings) {
      if (!byRule.has(f.id)) byRule.set(f.id, { id: f.id, sev: f.severity, targets: new Set() });
      byRule.get(f.id).targets.add(f.server || shortPath(f.file).split('/').pop());
    }
    const rules = [...byRule.values()].sort((a, b) => SEVERITIES.indexOf(a.sev) - SEVERITIES.indexOf(b.sev) || impact[b.id] - impact[a.id]);
    const maxGain = Math.max(1, ...Object.values(impact));
    const titleW = Math.min(48, Math.max(...rules.map((r) => RULES[r.id].title.length)));
    head('Fix first', c.dim('score gain'));
    push();
    rules.forEach((r, i) => {
      const t = RULES[r.id].title.length > titleW ? `${RULES[r.id].title.slice(0, titleW - 1)}…` : RULES[r.id].title;
      const gain = impact[r.id];
      const cells = Math.max(gain > 0 ? 1 : 0, Math.round((gain / maxGain) * 8));
      const meter = c.green('■'.repeat(cells)) + c.dim('·'.repeat(8 - cells));
      const targets = [...r.targets].join(', ');
      const tw = W - 4 - 3 - titleW - 2 - 14;
      push(`  ${c.dim(String(i + 1).padStart(2))} ${t.padEnd(titleW)}  ${c.cyan((targets.length > tw ? `${targets.slice(0, tw - 1)}…` : targets).padEnd(tw))} ${meter} ${c.green(gain > 0 ? `+${gain}` : '')}`);
      if (verbose) for (const m of wrap(RULES[r.id].fix, '', W - 10)) push(`     ${c.dim(m)}`);
    });
    push();
  }

  // Footer
  if (verbose) {
    head('Scanned');
    for (const cfg of configs) push(`  ${cfg.source.client.padEnd(15)} ${shortPath(cfg.source.path, 56)}  ${cfg.error ? c.yellow(cfg.error) : c.dim(`${cfg.servers.length} server${cfg.servers.length === 1 ? '' : 's'}`)}`);
    push();
  } else {
    for (const cfg of configs.filter((x) => x.error)) push(c.yellow(`  ! could not read ${shortPath(cfg.source.path)}: ${cfg.error}`));
  }
  if (liveErrors?.length) {
    for (const line of wrap(`! could not list tools for ${liveErrors.map((e) => `${e.server} (${e.error})`).join(', ')}`, '', W - 2)) push(c.yellow(`  ${line}`));
  }
  const tips = [];
  if (findings.length && !verbose) tips.push('-v  show each finding in its config file, with the fix');
  tips.push('--html  write a report you can open in a browser');
  if (!result.live && !toolsScanned && servers > 0) tips.push('--connect  also check tool descriptions (starts your servers)');
  for (const t of tips) { const [flag, ...rest] = t.split('  '); push(`  ${c.dim('›')} ${c.bold(flag.padEnd(10))} ${c.dim(rest.join('  '))}`); }
  push();
  return L.join('\n');
}
