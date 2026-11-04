// Terminal output, modelled on compiler diagnostics: each finding points at
// the file, line and key it came from, followed by a short summary.
import { RULES, SEVERITIES } from '../rules.js';
import { displayPath, POISON } from '../checks.js';
import { impactByRule } from '../score.js';
import { maskLine } from '../locate.js';

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

export function renderTerminal(result, { color = false, verbose = false, width = 100 } = {}) {
  const c = makeColors(color);
  const W = Math.min(Math.max(width, 60), 100);
  const sev = { critical: (s) => c.bold(c.red(s)), high: (s) => c.bold(c.red(s)), medium: (s) => c.bold(c.yellow(s)), low: (s) => c.bold(c.blue(s)), info: (s) => c.bold(c.gray(s)) };
  const gut = (s) => c.blue(s);
  const { score, findings, configs, servers, toolsScanned, liveErrors } = result;
  const textOf = Object.fromEntries(configs.map((x) => [x.source.path, x.text]));
  const L = [];
  const push = (s = '') => L.push(s);

  const clients = [...new Set(configs.map((x) => x.source.client))];
  push(c.dim(`mcpsafe ${result.version}: ${configs.length} config file${configs.length === 1 ? '' : 's'}, ${servers} server${servers === 1 ? '' : 's'}${toolsScanned ? `, ${toolsScanned} tool descriptions` : ''}${clients.length ? ` (${clients.join(', ')})` : ''}`));
  push();

  if (!configs.length) {
    push(`${c.yellow('No MCP config files found.')} Pass a file or folder: mcpsafe ./path`);
    return L.join('\n');
  }

  const gutterW = Math.max(1, ...findings.map((f) => String(f.line || '').length));
  const note = (label, text, pad) => {
    for (const [i, line] of wrap(text, '', W - pad.length - label.length - 6).entries()) push(i ? `${pad}   ${' '.repeat(label.length + 2)}${line}` : `${pad} ${gut('=')} ${c.bold(`${label}:`)} ${line}`);
  };
  for (const f of findings) {
    push(`${sev[f.severity](`${f.severity}[${f.id}]`)}${c.bold(`: ${f.title}`)}`);
    const text = textOf[f.file];
    const lines = text ? text.split('\n') : [];
    const src = f.line ? maskLine(lines[f.line - 1] ?? '').replace(/\t/g, '  ') : null;
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

  // Summary
  const counts = SEVERITIES.filter((s) => score.counts[s]).map((s) => `${score.counts[s]} ${s}`).join(', ');
  const g = score.grade;
  const tone = g === 'A' || g === 'B' ? c.green : g === 'C' || g === 'D' ? c.yellow : c.red;
  push(`${c.bold('score:')} ${tone(c.bold(`${score.value}/100 (${g})`))}${findings.length ? `, ${findings.length} finding${findings.length === 1 ? '' : 's'}: ${counts}` : ', no findings'}`);

  if (findings.length) {
    const impact = impactByRule(findings);
    const byRule = new Map();
    for (const f of findings) {
      if (!byRule.has(f.id)) byRule.set(f.id, { id: f.id, sev: f.severity, targets: new Set() });
      byRule.get(f.id).targets.add(f.server || displayPath(f.file).split(/[\\/]/).pop());
    }
    const rules = [...byRule.values()].sort((a, b) => SEVERITIES.indexOf(a.sev) - SEVERITIES.indexOf(b.sev) || impact[b.id] - impact[a.id]);
    const titleW = Math.min(46, Math.max(...rules.map((r) => RULES[r.id].title.length)));
    push();
    push(c.bold('fix first:'));
    for (const r of rules) {
      const gain = impact[r.id] > 0 ? `+${impact[r.id]}` : '';
      const title = RULES[r.id].title.length > titleW ? `${RULES[r.id].title.slice(0, titleW - 1)}…` : RULES[r.id].title;
      push(`  ${c.green(gain.padStart(3))}  ${title.padEnd(titleW)}  ${c.dim([...r.targets].join(', '))}`);
    }
  }
  push();

  if (verbose) {
    push(c.bold('scanned:'));
    for (const cfg of configs) push(`  ${cfg.source.client.padEnd(15)} ${displayPath(cfg.source.path)}  ${cfg.error ? c.yellow(cfg.error) : c.dim(`${cfg.servers.length} server${cfg.servers.length === 1 ? '' : 's'}`)}`);
    push();
  } else {
    for (const cfg of configs.filter((x) => x.error)) push(c.yellow(`warning: could not read ${displayPath(cfg.source.path)}: ${cfg.error}`));
  }
  if (liveErrors?.length) {
    for (const line of wrap(`warning: could not list tools for ${liveErrors.map((e) => `${e.server} (${e.error})`).join(', ')}`, '', W)) push(c.yellow(line));
    push();
  }
  if (!result.live && !toolsScanned && servers > 0) {
    push(c.dim('Tool descriptions were not checked. Run with --connect to start each server and inspect them.'));
  }
  return L.join('\n').replace(/\n+$/, '\n');
}
