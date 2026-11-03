import { RULES, SEVERITIES } from '../rules.js';
import { displayPath } from '../checks.js';
import { impactByRule } from '../score.js';

export function makeColors(enabled) {
  const wrap = (open, close) => (s) => (enabled ? `\x1b[${open}m${s}\x1b[${close}m` : String(s));
  return {
    bold: wrap(1, 22), dim: wrap(2, 22), italic: wrap(3, 23), red: wrap(31, 39), green: wrap(32, 39), yellow: wrap(33, 39),
    blue: wrap(34, 39), magenta: wrap(35, 39), cyan: wrap(36, 39), gray: wrap(90, 39),
    bgRed: wrap('41;97', '49;39'), bgYellow: wrap('43;30', '49;39'), bgGreen: wrap('42;30', '49;39'),
  };
}

const SEV_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };
const SEV_ICON = { critical: '✖', high: '✖', medium: '▲', low: '●', info: '○' };
const VERDICT = { A: 'Looks good', B: 'Minor issues', C: 'Needs attention', D: 'At risk', F: 'High risk' };

// eslint-disable-next-line no-control-regex
const visible = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, '').length;
const padTo = (s, n) => s + ' '.repeat(Math.max(0, n - visible(s)));

// Word-wrap plain text so long messages stay readable in narrow terminals.
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

// Shorten long paths in the middle: ~/Library/…/claude_desktop_config.json
function shortPath(p, max = 48) {
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
  const W = Math.min(Math.max(width, 60), 110);
  const sevColor = { critical: (s) => c.bold(c.red(s)), high: c.red, medium: c.yellow, low: c.blue, info: c.gray };
  const { score, findings, configs, servers, toolsScanned, liveErrors } = result;
  const g = score.grade;
  const tone = g === 'A' || g === 'B' ? c.green : g === 'C' || g === 'D' ? c.yellow : c.red;
  const L = [];
  const push = (s = '') => L.push(s);

  // ── header ──────────────────────────────────────────────
  push();
  push(`  ${c.green('◆')} ${c.bold('mcpsafe')} ${c.dim(`v${result.version}`)}  ${c.dim('MCP security audit')}`);
  push();

  // ── score box ───────────────────────────────────────────
  const inner = Math.min(W - 6, 76);
  const barW = inner;
  const CW = inner + 4; // content width matching the score box
  const filled = Math.round((score.value / 100) * barW);
  const bar = tone('━'.repeat(filled)) + c.gray('━'.repeat(barW - filled));
  const counts = SEVERITIES.filter((s) => s !== 'info' || score.counts.info)
    .map((s) => (score.counts[s] ? sevColor[s](`● ${score.counts[s]} ${s}`) : c.dim(`○ 0 ${s}`))).join('   ');
  const clients = [...new Set(configs.map((x) => x.source.client))];
  const scanned = [`${configs.length} file${configs.length === 1 ? '' : 's'}`, `${servers} server${servers === 1 ? '' : 's'}`, toolsScanned ? `${toolsScanned} tools` : null].filter(Boolean).join(' · ');
  const box = [
    `${c.bold(tone(`${score.value}`))}${c.dim(' / 100')}   ${tone(c.bold(`Grade ${g}`))}   ${c.bold(VERDICT[g])}`,
    bar,
    counts,
    c.dim(`${scanned}${clients.length ? `  ·  ${clients.join(', ')}` : ''}`),
  ];
  push(c.dim(`  ╭${'─'.repeat(inner + 2)}╮`));
  for (const [i, line] of box.entries()) {
    push(`  ${c.dim('│')} ${padTo(line, inner)} ${c.dim('│')}`);
    if (i === 0) push(`  ${c.dim('│')} ${' '.repeat(inner)} ${c.dim('│')}`);
  }
  push(c.dim(`  ╰${'─'.repeat(inner + 2)}╯`));
  push();

  if (!configs.length) {
    push(c.yellow('  No MCP config files found.') + c.dim(' Pass a file or folder: mcpsafe ./path'));
    push();
    return L.join('\n');
  }

  // ── findings, grouped by server ─────────────────────────
  if (findings.length) {
    push(`  ${c.bold('Findings')}`);
    push();
    const groups = new Map();
    for (const f of findings) {
      const key = f.server ? `${f.server}\0${f.file}` : `\0${f.file}`;
      if (!groups.has(key)) groups.set(key, { server: f.server, client: f.client, file: f.file, items: [] });
      groups.get(key).items.push(f);
    }
    for (const grp of groups.values()) {
      const worst = grp.items[0].severity;
      const name = grp.server ? c.bold(grp.server) : c.bold(shortPath(grp.file, 40).split('/').pop());
      push(`  ${sevColor[worst]('┃')} ${name}  ${c.dim(`${grp.client ? `${grp.client} · ` : ''}${shortPath(grp.file)}`)}`);
      for (const f of grp.items) {
        const label = sevColor[f.severity](`${SEV_ICON[f.severity]} ${SEV_LABEL[f.severity].padEnd(8)}`);
        const title = `${label}  ${f.title}`;
        const id = c.dim(f.id);
        const gap = Math.max(2, CW - 4 - visible(title) - f.id.length);
        push(`  ${sevColor[worst]('┃')}   ${title}${' '.repeat(gap)}${id}`);
        for (const line of wrap(f.message, '', CW - 16)) push(`  ${sevColor[worst]('┃')}               ${c.dim(line)}`);
        if (verbose && f.evidence) push(`  ${sevColor[worst]('┃')}               ${c.gray(`↳ ${f.evidence.replace(/\s+/g, ' ').slice(0, CW - 18)}`)}`);
      }
      push();
    }

    // ── fix first ─────────────────────────────────────────
    const impact = impactByRule(findings);
    const byRule = new Map();
    for (const f of findings) {
      if (!byRule.has(f.id)) byRule.set(f.id, { id: f.id, sev: f.severity, targets: new Set() });
      byRule.get(f.id).targets.add(f.server || shortPath(f.file, 30).split('/').pop());
    }
    const rules = [...byRule.values()].sort((a, b) => SEVERITIES.indexOf(a.sev) - SEVERITIES.indexOf(b.sev) || impact[b.id] - impact[a.id]);
    const TOP = verbose ? rules.length : 5;
    push(`  ${c.bold('Fix these first')}`);
    push();
    rules.slice(0, TOP).forEach((r, i) => {
      const gain = impact[r.id] > 0 ? c.green(`+${impact[r.id]} pts`) : '';
      const head = `  ${c.bold(`${i + 1}.`)} ${r.sev === 'critical' || r.sev === 'high' ? c.bold(RULES[r.id].title) : RULES[r.id].title}  ${c.cyan([...r.targets].slice(0, 3).join(', '))}${r.targets.size > 3 ? c.dim(` +${r.targets.size - 3}`) : ''}`;
      push(gain ? `${head}${' '.repeat(Math.max(2, CW + 2 - visible(head) - visible(gain)))}${gain}` : head);
      for (const line of wrap(RULES[r.id].fix, '', CW - 3)) push(`     ${c.dim(line)}`);
    });
    if (rules.length > TOP) push(c.dim(`\n     …and ${rules.length - TOP} more. See them all with ${c.bold('--verbose')} or ${c.bold('--html')}.`));
    push();
  } else {
    push(`  ${c.green('✔')} ${c.bold('No issues found.')} ${c.dim(`Checked ${servers} server${servers === 1 ? '' : 's'} against ${Object.keys(RULES).length} rules.`)}`);
    push();
  }

  // ── files + footer ──────────────────────────────────────
  if (verbose || !findings.length) {
    push(`  ${c.bold('Scanned')}`);
    for (const cfg of configs) {
      const n = cfg.servers.length;
      push(`  ${c.dim('·')} ${padTo(cfg.source.client, 15)} ${shortPath(cfg.source.path, 60)}  ${cfg.error ? c.yellow(cfg.error) : c.dim(`${n} server${n === 1 ? '' : 's'}`)}`);
    }
    push();
  } else {
    const broken = configs.filter((x) => x.error);
    if (broken.length) { push(c.yellow(`  ! Could not read ${broken.map((x) => shortPath(x.source.path)).join(', ')}`)); push(); }
  }
  if (liveErrors?.length) {
    for (const line of wrap(`Could not list tools for: ${liveErrors.map((e) => `${e.server} (${e.error})`).join(', ')}`, '', W - 4)) push(c.yellow(`  ${line}`));
    push();
  }
  if (!result.live && !toolsScanned && servers > 0) {
    for (const line of wrap('Tip: add --connect to inspect tool descriptions for hidden instructions (this starts your servers).', '', CW)) push(c.dim(`  ${line}`));
    push();
  }
  return L.join('\n');
}
