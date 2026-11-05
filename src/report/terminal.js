// Terminal output. The default view is a summary: logo, score, severity
// chart, findings grouped by server and the fixes ranked by score gain.
// --verbose adds compiler-style diagnostics that point at the exact config
// line of every finding.
import { RULES, SEVERITIES } from '../rules.js';
import { displayPath, poisonSpans, spanRank } from '../checks.js';
import { impactByRule } from '../score.js';
import { allConfigSecrets, snippet } from '../locate.js';
import { safe, dispWidth, splitW, truncW, padW, unreadSummary } from './text.js';

export function makeColors(enabled) {
  const wrap = (open, close) => (s) => (enabled ? `\x1b[${open}m${s}\x1b[${close}m` : String(s));
  return {
    bold: wrap(1, 22), dim: wrap(2, 22), red: wrap(31, 39), green: wrap(32, 39), yellow: wrap(33, 39),
    blue: wrap(34, 39), magenta: wrap(35, 39), cyan: wrap(36, 39), gray: wrap(90, 39),
  };
}

// Columns a string takes on screen, without colour codes and counting wide
// characters as two.
const visible = dispWidth;

// Word-wrap plain text to `width` columns. A word longer than a line is split.
export function wrap(text, indent, width) {
  const max = Math.max(20, width - indent.length);
  const lines = [];
  let cur = '';
  for (let word of String(text).split(/\s+/)) {
    if (!word) continue;
    while (dispWidth(word) > max) {
      const room = cur ? max - dispWidth(cur) - 1 : max;
      if (room < 8) { lines.push(cur); cur = ''; continue; }
      const [head, rest] = splitW(word, room);
      lines.push(cur ? `${cur} ${head}` : head);
      cur = '';
      word = rest;
    }
    if (cur && dispWidth(cur) + 1 + dispWidth(word) > max) { lines.push(cur); cur = word; } else cur = cur ? `${cur} ${word}` : word;
  }
  if (cur) lines.push(cur);
  return lines;
}

// File name of a path, for either separator.
const baseName = (p) => safe(String(displayPath(p) || '').split(/[\\/]/).pop());

// Where on the line to put the ^^^ underline: the last key of the JSON path.
function underline(text, jsonPath) {
  const start = text.search(/\S/);
  if (start < 0) return null;
  const key = (jsonPath || '').match(/"[^"]+"|[^.[\]"]+/g)?.filter((k) => !/^\d+$/.test(k)).pop()?.replace(/"/g, '');
  const at = key ? text.indexOf(`"${key}"`) : -1;
  // The line without trailing commas, brackets and spaces. Scanned from the end, since a
  // regex for this backtracks on a long run of "{" that does not reach the end.
  let end = text.length;
  while (end > 0 && /[,{[\s]/.test(text[end - 1])) end--;
  if (at >= 0 && !/\[\d+\]$/.test(jsonPath)) return [at, Math.max(at + key.length + 2, end) - at];
  return [start, Math.max(1, end - start)];
}

function renderDiagnostics(result, { color = false, width = 100 } = {}) {
  const c = makeColors(color);
  const W = Math.min(Math.max(width, 38), 100);
  const sev = { critical: (s) => c.bold(c.red(s)), high: (s) => c.bold(c.red(s)), medium: (s) => c.bold(c.yellow(s)), low: (s) => c.bold(c.blue(s)), info: (s) => c.bold(c.gray(s)) };
  const gut = (s) => c.blue(s);
  const { findings, configs } = result;
  const textOf = Object.fromEntries(configs.map((x) => [x.source.path, x.text]));
  // Secrets of every scanned file, so a value repeated in another file is hidden there too.
  const known = allConfigSecrets(configs.map((x) => x.text));
  const L = [];
  const push = (s = '') => L.push(s);
  const gutterW = Math.max(1, ...findings.map((f) => String(f.line || '').length));
  const note = (label, text, pad) => {
    for (const [i, line] of wrap(text, '', W - pad.length - label.length - 6).entries()) push(i ? `${pad}   ${' '.repeat(label.length + 2)}${line}` : `${pad} ${gut('=')} ${c.bold(`${label}:`)} ${line}`);
  };
  for (const f of findings) {
    // The title wraps under itself, after "severity[ID]: ".
    const tag = `${f.severity}[${f.id}]`;
    const titleLines = wrap(f.title, '', W - tag.length - 2);
    titleLines.forEach((t, i) => push(i ? `${' '.repeat(tag.length + 2)}${c.bold(t)}` : `${sev[f.severity](tag)}${c.bold(`: ${t}`)}`));
    // Masked with the whole file as context, so a value after a --flag line is hidden too.
    const src = f.line ? snippet(textOf[f.file], f.line, 0, known)?.[0]?.text ?? null : null;
    const num = f.line ? String(f.line).padStart(gutterW) : '';
    const pad = ' '.repeat(gutterW);
    const message = safe(f.message);
    const at = f.line ? `:${f.line}` : '';
    if (f.file) push(`${pad}${gut('-->')} ${shortPath(f.file, Math.max(12, W - pad.length - 5 - at.length))}${at}`);
    const srcLine = src == null ? null : safe(src);
    if (srcLine != null && srcLine.trim()) {
      // Columns, not string indexes, so wide characters keep the carets aligned.
      const [at, n] = underline(srcLine, f.jsonPath) || [0, 1];
      const room = W - pad.length - 4;
      const shown = truncW(srcLine, room);
      const col = Math.min(dispWidth(srcLine.slice(0, at)), Math.max(0, dispWidth(shown) - 1));
      const carets = '^'.repeat(Math.max(1, Math.min(dispWidth(srcLine.slice(at, at + n)), dispWidth(shown) - col)));
      push(`${pad} ${gut('|')}`);
      push(`${gut(num)} ${gut('|')} ${shown}`);
      const label = dispWidth(message) + col + carets.length + 1 < room ? ` ${message}` : '';
      push(`${pad} ${gut('|')} ${' '.repeat(col)}${sev[f.severity](carets)}${label ? sev[f.severity](label) : ''}`);
      if (!label) note('note', message, pad);
    } else {
      push(`${pad} ${gut('|')}`);
      note('note', message, pad);
    }
    if (f.id === 'MCS016' && f.evidence) {
      const found = [];
      const spans = poisonSpans(f.evidence).sort((a, b) => spanRank(a.kind) - spanRank(b.kind) || a.start - b.start);
      for (const h of spans) { const t = f.evidence.slice(h.start, h.end).replace(/\s+/g, ' ').trim(); if (t) found.push(`"${safe(t.length > 160 ? `${t.slice(0, 157)}...` : t)}"`); }
      if (found.length) note('found', [...new Set(found)].slice(0, 4).join(', '), pad);
    }
    if (f.server) note('server', safe(`${f.server}${f.client ? ` (${f.client})` : ''}`), pad);
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
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

// A path for display, made safe and shortened to `max` columns by leaving
// out folders from the middle. The file name is kept whenever it fits.
function shortPath(p, max = 52) {
  const d = safe(displayPath(p) || '');
  if (dispWidth(d) <= max) return d;
  const sep = d.includes('\\') && !d.includes('/') ? '\\' : '/';
  const parts = d.split(/[\\/]/);
  const last = parts.pop();
  let head = parts.shift();
  const join = (h) => `${h}${sep}…${sep}${last}`;
  if (dispWidth(join(head)) > max) return truncW(dispWidth(last) + 2 <= max ? `…${sep}${last}` : last, max);
  while (parts.length && dispWidth(join(`${head}${sep}${parts[0]}`)) <= max) head = `${head}${sep}${parts.shift()}`;
  return join(head);
}

// Config files that could not be read or parsed. The CLI puts them in
// result.errors; older callers only have the error on each config.
const scanErrors = (result) => result.errors ?? result.configs.filter((x) => x.error).map((x) => ({ path: x.source.path, error: x.error }));

export function renderTerminal(result, { color = false, verbose = false, html = false, width = 100 } = {}) {
  const c = makeColors(color);
  const W = Math.min(Math.max(width, 40), 96);
  const { score, findings, configs, servers, toolsScanned, liveErrors } = result;
  const errors = scanErrors(result);
  const incomplete = errors.length > 0;
  const missingPaths = errors.filter((e) => e.missing);
  const g = score.grade;
  const tone = g === 'A' || g === 'B' ? c.green : g === 'C' || g === 'D' ? c.yellow : c.red;
  const sevC = { critical: (s) => c.bold(c.red(s)), high: c.red, medium: c.yellow, low: c.blue, info: c.gray };
  const L = [];
  const push = (s = '') => L.push(s);
  const head = (t, right = '') => {
    const gap = W - 4 - visible(t) - visible(right);
    push(`  ${c.bold(t)}${right && gap >= 2 ? `${' '.repeat(gap)}${right}` : ''}`);
    push(`  ${c.dim('─'.repeat(W - 4))}`);
  };
  // Wrapped text: the first line after `first`, the rest indented to match.
  const para = (first, text, style = (s) => s) => {
    const indent = ' '.repeat(visible(first));
    wrap(text, '', W - 2 - indent.length).forEach((line, i) => push(`${i ? indent : first}${style(line)}`));
  };
  // A "! ..." warning: the lines after the first start under the text, not under the "!".
  const warn = (text) => para(`  ${c.yellow('!')} `, text, c.yellow);

  // Logo
  const clients = [...new Set(configs.map((x) => safe(x.source.client)))];
  const logo = big('mcpsafe');
  const side = [
    c.dim(`v${result.version}`),
    'security audit for MCP servers',
    c.dim(`${plural(configs.length, 'file')} · ${plural(servers, 'server')}${toolsScanned ? ` · ${plural(toolsScanned, 'tool')}` : ''}`),
  ];
  push();
  if (2 + visible(logo[0]) + 3 + Math.max(...side.map(visible)) <= W) {
    logo.forEach((row, i) => push(`  ${c.cyan(c.bold(row))}   ${side[i]}`));
  } else {
    for (const row of logo) push(`  ${c.cyan(c.bold(row))}`);
    push();
    for (const s of side) push(`  ${s}`);
  }
  push();

  if (!configs.length && !toolsScanned && !findings.length) {
    // Nothing was read, so there is no score: a grade here would read as a pass.
    if (missingPaths.length) for (const e of missingPaths) warn(`path not found: ${shortPath(e.path)}`);
    else para('  ', 'No MCP config files found. Pass a file or folder: mcpsafe ./path', c.yellow);
    push();
    return L.join('\n');
  }
  if (!configs.length) {
    para('  ', `No MCP config files were scanned. Checked ${plural(toolsScanned, 'tool')} from the tools file.`, c.dim);
    push();
  }

  // Score: big digits, grade, bar
  const digits = big(score.value);
  const grade = big(g);
  const digW = Math.max(9, digits[0].length);
  const left = 2 + digW + 1 + 3 + 3;
  const verdict = incomplete ? c.yellow('incomplete') : tone(VERDICT[g]);
  const scoreText = (gap) => `${c.bold('score')} ${tone(c.bold(score.value))}${c.dim('/100')}${gap}${c.bold('grade')} ${tone(c.bold(g))}`;
  let top = `${scoreText('   ')}   ${verdict}`;
  let verdictBelow = false;
  if (left + visible(top) > W) { top = scoreText('  '); verdictBelow = true; }
  const barW = Math.max(10, Math.min(50, W - left - 8));
  const bands = Array(barW).fill(' ');
  for (const [ch, at] of [['F', 0.3], ['D', 0.65], ['C', 0.75], ['B', 0.85], ['A', 0.95]]) bands[Math.min(barW - 1, Math.floor(at * barW))] = ch;
  const filled = Math.round((score.value / 100) * barW);
  const bar = tone('█'.repeat(filled)) + c.dim('░'.repeat(barW - filled));
  const right = [top, bar, bands.map((ch) => (ch === g ? tone(c.bold(ch)) : c.dim(ch))).join('')];
  for (let i = 0; i < 3; i++) push(`  ${tone(c.bold(digits[i].padEnd(digW)))} ${tone(grade[i])}   ${right[i]}`);
  if (verdictBelow) push(`  ${verdict}`);
  if (incomplete) {
    push();
    warn(`Incomplete scan: ${unreadSummary(errors)}, so the score covers only the files that were read.`);
  }
  push();

  if (!findings.length) {
    const checked = configs.length || !toolsScanned ? plural(servers, 'server') : plural(toolsScanned, 'tool');
    const detail = `${checked} checked against ${Object.keys(RULES).length} rules${clients.length ? ` in ${clients.join(', ')}` : ''}.`;
    const mark = incomplete ? c.yellow('!') : c.green('✔');
    const label = incomplete ? 'No findings in the files that were read.' : 'No findings.';
    if (4 + label.length + 1 + dispWidth(detail) <= W - 2) push(`  ${mark} ${c.bold(label)} ${c.dim(detail)}`);
    else { push(`  ${mark} ${c.bold(label)}`); para('    ', detail, c.dim); }
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
      for (const line of renderDiagnostics(result, { color, width: W - 2 })) push(line ? `  ${line}` : '');
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
        const name = truncW(safe(first.server) || baseName(first.file) || 'unknown', Math.max(16, Math.floor((W - 4) * 0.6)));
        const room = W - 4 - dispWidth(name) - 2;
        // Client and path after the name, leaving out the client, then the
        // path, when the line has no room for them.
        let client = first.client ? `${safe(first.client)} · ` : '';
        if (room - dispWidth(client) < 16) client = '';
        const where = room >= 12 ? truncW(`${client}${shortPath(first.file, room - dispWidth(client))}`, room) : '';
        push(`  ${sevC[items[0].severity]('●')} ${c.bold(name)}${where ? `  ${c.dim(where)}` : ''}`);
        items.forEach((f, i) => {
          const last = i === items.length - 1;
          const branch = c.dim(last ? '└─' : '├─');
          const stem = c.dim(last ? '  ' : '│ ');
          const line = f.line ? `:${f.line}` : '';
          const tag = sevC[f.severity](SEV_SHORT[f.severity]);
          const title = safe(f.title);
          const gap = W - 13 - dispWidth(title) - line.length;
          if (gap >= 2) {
            push(`  ${branch} ${tag}  ${title}${line ? `${' '.repeat(gap)}${c.dim(line)}` : ''}`);
          } else {
            // Narrow: wrap the title and put the line number right after it.
            const parts = wrap(title, '', W - 13 - (line ? line.length + 1 : 0));
            parts.forEach((p, j) => push(`  ${j ? stem : branch} ${j ? '      ' : `${tag}  `}${p}${line && j === parts.length - 1 ? ` ${c.dim(line)}` : ''}`));
          }
          for (const m of wrap(safe(f.message), '', W - 16)) push(`  ${stem}       ${c.dim(m)}`);
        });
        push();
      }
    }

    // Fix first
    const impact = impactByRule(findings);
    const byRule = new Map();
    for (const f of findings) {
      if (!byRule.has(f.id)) byRule.set(f.id, { id: f.id, sev: f.severity, targets: new Set() });
      byRule.get(f.id).targets.add(safe(f.server) || baseName(f.file) || 'unknown');
    }
    const rules = [...byRule.values()].sort((a, b) => SEVERITIES.indexOf(a.sev) - SEVERITIES.indexOf(b.sev) || impact[b.id] - impact[a.id]);
    const maxGain = Math.max(1, ...Object.values(impact));
    const titleW = Math.min(48, Math.max(...rules.map((r) => dispWidth(RULES[r.id].title))));
    // Columns: number, title, targets, an 8-cell meter and the gain. When
    // the targets would not get enough room they go on a line of their own,
    // and on a narrow terminal the meter is left out.
    const tw = W - 23 - titleW;
    const wide = tw >= 14;
    const showMeter = wide || W >= 64;
    head('Fix first', c.dim('score gain'));
    push();
    rules.forEach((r, i) => {
      const title = RULES[r.id].title;
      const gain = impact[r.id];
      const gainText = gain > 0 ? `+${gain}` : '';
      const num = c.dim(String(i + 1).padStart(2));
      const targets = [...r.targets].join(', ');
      const cells = Math.max(gain > 0 ? 1 : 0, Math.round((gain / maxGain) * 8));
      const meter = showMeter ? ` ${c.green('■'.repeat(cells))}${c.dim('·'.repeat(8 - cells))}` : '';
      if (wide) {
        push(`  ${num} ${padW(truncW(title, titleW), titleW)}  ${c.cyan(padW(truncW(targets, tw), tw))}${meter} ${c.green(gainText)}`);
      } else {
        const room = W - 11 - (showMeter ? 9 : 0);
        const parts = wrap(title, '', room);
        parts.forEach((p, j) => push(j ? `     ${p}` : `  ${num} ${padW(p, room)}${meter}${c.green(gainText.padStart(4))}`));
        push(`     ${c.cyan(truncW(targets, W - 7))}`);
      }
      if (verbose) for (const m of wrap(RULES[r.id].fix, '', W - 10)) push(`     ${c.dim(m)}`);
    });
    push();
  }

  // Footer
  if (verbose) {
    head('Scanned');
    for (const cfg of configs) {
      const client = padW(safe(cfg.source.client), 15);
      const status = cfg.error ? safe(cfg.error) : plural(cfg.servers.length, 'server');
      const room = W - 2 - 16 - 2 - dispWidth(status);
      const style = cfg.error ? c.yellow : c.dim;
      if (room >= 16) push(`  ${client} ${shortPath(cfg.source.path, Math.min(56, room))}  ${style(status)}`);
      else { push(`  ${client} ${shortPath(cfg.source.path, W - 2 - 16)}`); para('    ', status, style); }
    }
    for (const e of missingPaths) warn(`path not found: ${shortPath(e.path)}`);
    push();
  } else {
    for (const cfg of configs.filter((x) => x.error)) warn(`could not read ${shortPath(cfg.source.path)}: ${safe(cfg.error)}`);
    for (const e of missingPaths) warn(`path not found: ${shortPath(e.path)}`);
  }
  if (liveErrors?.length) {
    warn(`could not list tools for ${liveErrors.map((e) => `${safe(e.server)} (${safe(e.error)})`).join(', ')}`);
  }
  // Warnings above end with a blank line before the tips.
  if (L[L.length - 1] !== '') push();
  const tips = [];
  if (findings.length && !verbose) tips.push('-v  show each finding in its config file, with the fix');
  if (!html) tips.push('--html  write a report you can open in a browser');
  if (!result.live && !toolsScanned && servers > 0) tips.push('--connect  also check tool descriptions (starts your servers)');
  for (const t of tips) {
    const [flag, ...rest] = t.split('  ');
    wrap(rest.join('  '), '', W - 17).forEach((p, j) => push(j ? `${' '.repeat(15)}${c.dim(p)}` : `  ${c.dim('›')} ${c.bold(flag.padEnd(10))} ${c.dim(p)}`));
  }
  push();
  return L.join('\n');
}
