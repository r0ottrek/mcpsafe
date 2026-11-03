// Self-contained HTML report: one file, no network requests, light and dark.
import { RULES, SEVERITIES } from '../rules.js';
import { displayPath, POISON } from '../checks.js';
import { snippet } from '../locate.js';
import { impactByRule } from '../score.js';
import { launchedPackages, effectiveCommand } from '../packages.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

export const LOGO = `<svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2.5 4.5 7v8.2c0 7.1 4.9 12.6 11.5 14.3 6.6-1.7 11.5-7.2 11.5-14.3V7L16 2.5Z" fill="currentColor" opacity=".16"/><path d="M16 2.5 4.5 7v8.2c0 7.1 4.9 12.6 11.5 14.3 6.6-1.7 11.5-7.2 11.5-14.3V7L16 2.5Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M11 12.5v2.2a5 5 0 0 0 10 0v-2.2M13 9.5v3M19 9.5v3M16 19.7V23" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`;

const VERDICT = {
  A: ['Looks good', 'Nothing serious stands out in your MCP setup.'],
  B: ['Minor issues', 'A few small things are worth tightening up.'],
  C: ['Needs attention', 'Some settings make it easier for a bad server or prompt to cause damage.'],
  D: ['At risk', 'Several settings put your files, credentials or machine at risk.'],
  F: ['High risk', 'Your current setup exposes credentials or lets untrusted code act on your machine.'],
};

const ICON = {
  check: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="m5 10.5 3.2 3.2L15 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  chevron: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="m7 5 5 5-5 5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  file: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 2.75h6.5L15.25 6.5v10.75H5Z M11.25 2.75V6.75h4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
  search: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="9" cy="9" r="5.25" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m13 13 4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
  moon: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M16.5 12.2A6.75 6.75 0 0 1 7.8 3.5a6.75 6.75 0 1 0 8.7 8.7Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>',
  sun: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="3.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10 2v2M10 16v2M2 10h2M16 10h2M4.3 4.3l1.4 1.4M14.3 14.3l1.4 1.4M4.3 15.7l1.4-1.4M14.3 5.7l1.4-1.4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
  print: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5.5 7.5V3h9v4.5M5.5 14H3.5V8.5a1 1 0 0 1 1-1h11a1 1 0 0 1 1 1V14h-2M6 11.5h8V17H6Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
};

// Escape text and wrap the phrases that triggered tool-poisoning rules in <mark>.
function markPoison(text) {
  const ranges = [];
  for (const [re] of POISON) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    let m;
    while ((m = g.exec(text))) { if (m[0]) ranges.push([m.index, m.index + m[0].length]); else g.lastIndex++; }
  }
  ranges.sort((a, b) => a[0] - b[0]);
  let out = '';
  let pos = 0;
  for (const [a, b] of ranges) {
    if (b <= pos) continue;
    const start = Math.max(a, pos);
    out += esc(text.slice(pos, start)) + `<mark>${esc(text.slice(start, b))}</mark>`;
    pos = b;
  }
  return out + esc(text.slice(pos));
}

// Minimal JSON syntax highlighting for one (already masked) line.
function highlight(line) {
  let out = '';
  let last = 0;
  const re = /"(?:[^"\\]|\\.)*"(\s*:)?|\b(?:true|false|null)\b|-?\b\d+(?:\.\d+)?\b|\/\/.*$/g;
  let m;
  while ((m = re.exec(line))) {
    out += esc(line.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith('//')) out += `<span class="tc">${esc(tok)}</span>`;
    else if (tok.startsWith('"')) {
      const str = m[1] ? tok.slice(0, tok.length - m[1].length) : tok;
      out += `<span class="${m[1] ? 'tk' : 'ts'}">${esc(str)}</span>${m[1] ? esc(m[1]) : ''}`;
    } else out += `<span class="tn">${esc(tok)}</span>`;
    last = m.index + tok.length;
  }
  return out + esc(line.slice(last));
}

function launcher(s) {
  if (s.url) {
    try { const u = new URL(s.url); return `${s.transport === 'sse' ? 'sse' : u.protocol === 'http:' ? 'http' : 'https'} · ${u.host}${u.pathname === '/' ? '' : u.pathname}`; } catch { return s.url; }
  }
  const pkg = launchedPackages(s)[0];
  const { base } = effectiveCommand(s);
  if (pkg) return `${base} · ${pkg.spec}`;
  return [s.command, ...s.args].filter(Boolean).join(' ').slice(0, 80);
}

function gauge(value, grade) {
  // 240° arc gauge.
  const r = 78, cx = 100, cy = 100;
  const start = 150, sweep = 240;
  const pt = (deg) => [cx + r * Math.cos((deg * Math.PI) / 180), cy + r * Math.sin((deg * Math.PI) / 180)];
  const arc = (from, to) => {
    const [x1, y1] = pt(from), [x2, y2] = pt(to);
    return `M${x1.toFixed(2)} ${y1.toFixed(2)} A${r} ${r} 0 ${to - from > 180 ? 1 : 0} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
  };
  const end = start + (sweep * Math.max(value, 0.5)) / 100;
  return `<svg class="gauge" viewBox="0 0 200 172" role="img" aria-label="Score ${value} out of 100, grade ${grade}">
    <path d="${arc(start, start + sweep)}" class="g-track"/>
    <path d="${arc(start, end)}" class="g-value"/>
    <text x="100" y="104" text-anchor="middle" class="g-num">${value}</text>
    <text x="100" y="128" text-anchor="middle" class="g-of">out of 100</text>
    <text x="100" y="166" text-anchor="middle" class="g-grade">GRADE ${grade}</text>
  </svg>`;
}

export function renderHtml(result) {
  const { score, findings, configs, servers, toolsScanned, generatedAt, version } = result;
  const tone = { A: 'good', B: 'good', C: 'warn', D: 'warn', F: 'bad' }[score.grade];
  const [verdictTitle, verdictText] = VERDICT[score.grade];
  const serious = score.counts.critical + score.counts.high;
  const allServers = configs.flatMap((c) => c.servers);
  const clients = [...new Set(configs.map((c) => c.source.client))];
  const impact = impactByRule(findings);
  const textOf = Object.fromEntries(configs.map((c) => [c.source.path, c.text]));
  const when = new Date(generatedAt);
  const whenText = when.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });

  // ---- severity distribution bar ----
  const total = findings.length || 1;
  const dist = SEVERITIES.filter((s) => score.counts[s])
    .map((s) => `<span class="seg sv-${s}" style="flex:${score.counts[s] / total}" title="${score.counts[s]} ${s}"></span>`).join('');
  const legend = SEVERITIES.filter((s) => s !== 'info' || score.counts.info)
    .map((s) => `<span class="lg ${score.counts[s] ? '' : 'zero'}"><i class="dot sv-${s}"></i><b>${score.counts[s]}</b> ${s}</span>`).join('');

  // ---- priority fixes (one per rule, ordered by severity then impact) ----
  const byRule = new Map();
  for (const f of findings) {
    if (!byRule.has(f.id)) byRule.set(f.id, { id: f.id, sev: f.severity, targets: new Set(), count: 0 });
    const r = byRule.get(f.id);
    r.count++;
    r.targets.add(f.server || displayPath(f.file).split(/[\\/]/).pop());
    if (SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(r.sev)) r.sev = f.severity;
  }
  const rules = [...byRule.values()].sort((a, b) => SEVERITIES.indexOf(a.sev) - SEVERITIES.indexOf(b.sev) || impact[b.id] - impact[a.id]);
  const fixCard = (r, i) => `
      <li class="fix sv-${r.sev}">
        <div class="fix-top">
          <span class="rank">${i + 1}</span>
          <span class="pill sv-${r.sev}">${SEV_LABEL[r.sev]}</span>
          ${impact[r.id] > 0 ? `<span class="gain" title="Score gain if fixed">+${impact[r.id]} pts</span>` : ''}
        </div>
        <h3>${esc(RULES[r.id].title)}</h3>
        <p>${esc(RULES[r.id].fix)}</p>
        <div class="targets">${[...r.targets].slice(0, 6).map((t) => `<button class="tag" data-server="${esc(t)}">${esc(t)}</button>`).join('')}${r.targets.size > 6 ? `<span class="tag more">+${r.targets.size - 6}</span>` : ''}</div>
      </li>`;
  const topFixes = rules.slice(0, 6).map(fixCard).join('');
  const moreFixes = rules.slice(6).map((r, i) => fixCard(r, i + 6)).join('');

  // ---- server inventory ----
  const serverCards = allServers.map((s) => {
    const fs = findings.filter((f) => f.server === s.name && f.file === s.file);
    const worst = SEVERITIES.find((sev) => fs.some((f) => f.severity === sev));
    const counts = SEVERITIES.filter((sev) => fs.some((f) => f.severity === sev))
      .map((sev) => `<span class="mini"><i class="dot sv-${sev}"></i>${fs.filter((f) => f.severity === sev).length}</span>`).join('');
    return `
      <button class="server ${worst ? `sv-${worst}` : 'ok'}" data-server="${esc(s.name)}" type="button">
        <span class="s-head">
          <span class="s-name">${esc(s.name)}</span>
          ${worst ? `<span class="pill sv-${worst}">${SEV_LABEL[worst]}</span>` : `<span class="pill okp">${ICON.check}OK</span>`}
        </span>
        <code class="s-launch">${esc(launcher(s))}</code>
        <span class="s-meta"><span>${esc(s.client)}${s.scope === 'project' ? ' · project' : ''}${s.disabled ? ' · disabled' : ''}</span><span class="s-counts">${counts || '<span class="mini none">No findings</span>'}</span></span>
      </button>`;
  }).join('');

  // ---- findings ----
  const findingRows = findings.map((f, i) => {
    const snip = snippet(textOf[f.file], f.line);
    const code = snip ? `<div class="code"><div class="code-head">${ICON.file}<span>${esc(displayPath(f.file))}</span><span class="ln">line ${f.line}</span></div><pre>${snip.map((l) => `<span class="row${l.hit ? ' hit' : ''}"><span class="num">${l.n}</span><span class="src">${highlight(l.text) || ' '}</span></span>`).join('')}</pre></div>`
      : f.evidence ? `<div class="code"><div class="code-head">${ICON.file}<span>${esc(f.jsonPath && f.jsonPath.startsWith('tools.') ? `tool description · ${f.jsonPath.slice(6)}` : displayPath(f.file) || 'evidence')}</span></div><pre class="wrap"><span class="row"><span class="src">${f.id === 'MCS016' ? markPoison(f.evidence) : esc(f.evidence)}</span></span></pre></div>` : '';
    const search = [f.id, f.title, f.server, f.client, f.message, displayPath(f.file)].join(' ').toLowerCase();
    return `
      <details class="finding sv-${f.severity}" data-sev="${f.severity}" data-server="${esc(f.server || '')}" data-search="${esc(search)}"${f.severity === 'critical' || i < 2 ? ' open' : ''}>
        <summary>
          <span class="pill sv-${f.severity}">${SEV_LABEL[f.severity]}</span>
          <span class="f-title">${esc(f.title)}</span>
          <span class="f-where">${f.server ? `<b>${esc(f.server)}</b>` : `<b>${esc(displayPath(f.file).split(/[\\/]/).pop())}</b>`}<span>${esc(f.client || '')}</span></span>
          <span class="f-id">${esc(f.id)}</span>
          <span class="chev">${ICON.chevron}</span>
        </summary>
        <div class="f-body">
          <p class="f-msg">${esc(f.message)}</p>
          ${code}
          <div class="explain">
            <div><h4>Why it matters</h4><p>${esc(RULES[f.id].why)}</p></div>
            <div class="howto"><h4>How to fix</h4><p>${esc(f.fix)}</p></div>
          </div>
          <p class="loc"><span>${esc(displayPath(f.file))}${f.line ? `:${f.line}` : ''}</span>${f.jsonPath ? `<code>${esc(f.jsonPath)}</code>` : ''}</p>
        </div>
      </details>`;
  }).join('');

  const filterButtons = [`<button class="seg-btn active" data-filter="all">All <b>${findings.length}</b></button>`,
    ...SEVERITIES.filter((s) => score.counts[s]).map((s) => `<button class="seg-btn" data-filter="${s}"><i class="dot sv-${s}"></i>${SEV_LABEL[s]} <b>${score.counts[s]}</b></button>`)].join('');

  const fileRows = configs.map((c) => `
      <tr>
        <td><span class="client">${esc(c.source.client)}</span></td>
        <td><code>${esc(displayPath(c.source.path))}</code></td>
        <td class="r">${c.error ? `<span class="err">${esc(c.error)}</span>` : plural(c.servers.length, 'server')}</td>
        <td class="r">${c.source.scope}</td>
      </tr>`).join('');

  const favicon = `data:image/svg+xml,${encodeURIComponent(LOGO.replace('<svg ', '<svg xmlns="http://www.w3.org/2000/svg" color="#10b981" '))}`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>mcpsafe report · ${score.value}/100</title>
<link rel="icon" href="${favicon}">
<style>
:root{
  --bg:#f5f6f8;--surface:#ffffff;--raised:#fafbfc;--ink:#0e1116;--ink-2:#3b4250;--muted:#6a7383;--line:#e4e7ec;--line-2:#d5dae1;
  --brand:#0f9f6e;--brand-soft:#e3f6ee;--code-bg:#f7f8fa;--hit:#fff4e5;--hit-line:#f59e0b;
  --critical:#d92d36;--high:#ea580c;--medium:#c98a04;--low:#2f6fdb;--info:#6a7383;
  --critical-soft:#fdecec;--high-soft:#fff0e6;--medium-soft:#fdf5df;--low-soft:#e9f0fd;--info-soft:#eef0f3;
  --good:#0f9f6e;--warn:#d08a00;--bad:#d92d36;
  --tk:#7c3aed;--ts:#0f7a55;--tn:#b45309;--tc:#8a93a3;
  --shadow:0 1px 2px rgba(16,24,40,.04),0 1px 3px rgba(16,24,40,.06);
  --radius:14px;
  --sans:"Inter","Inter Variable",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:"JetBrains Mono","SF Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0a0c10;--surface:#111419;--raised:#151920;--ink:#e9edf2;--ink-2:#c3cad4;--muted:#8a94a3;--line:#21262e;--line-2:#2c323c;
  --brand:#34d399;--brand-soft:#0f2a20;--code-bg:#0d1014;--hit:#2a1f0c;--hit-line:#f5a524;
  --critical:#ff5c63;--high:#ff8a3d;--medium:#f5c33b;--low:#6ea8ff;--info:#8a94a3;
  --critical-soft:#2c1215;--high-soft:#2b1a0e;--medium-soft:#2a220c;--low-soft:#111f36;--info-soft:#1a1e25;
  --good:#34d399;--warn:#f5c33b;--bad:#ff5c63;
  --tk:#c4a1ff;--ts:#7ee2b8;--tn:#f5b971;--tc:#6b7483;
  --shadow:0 0 0 1px rgba(255,255,255,.02);
}}
:root[data-theme="dark"]{
  --bg:#0a0c10;--surface:#111419;--raised:#151920;--ink:#e9edf2;--ink-2:#c3cad4;--muted:#8a94a3;--line:#21262e;--line-2:#2c323c;
  --brand:#34d399;--brand-soft:#0f2a20;--code-bg:#0d1014;--hit:#2a1f0c;--hit-line:#f5a524;
  --critical:#ff5c63;--high:#ff8a3d;--medium:#f5c33b;--low:#6ea8ff;--info:#8a94a3;
  --critical-soft:#2c1215;--high-soft:#2b1a0e;--medium-soft:#2a220c;--low-soft:#111f36;--info-soft:#1a1e25;
  --good:#34d399;--warn:#f5c33b;--bad:#ff5c63;
  --tk:#c4a1ff;--ts:#7ee2b8;--tn:#f5b971;--tc:#6b7483;
  --shadow:0 0 0 1px rgba(255,255,255,.02);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 var(--sans);font-feature-settings:"cv11","ss01";-webkit-font-smoothing:antialiased}
svg{display:block}
button{font:inherit;color:inherit}
code,pre{font-family:var(--mono)}
.wrap-page{max-width:1120px;margin:0 auto;padding:0 20px 72px}

/* severity tokens */
.sv-critical{--c:var(--critical);--cs:var(--critical-soft)}.sv-high{--c:var(--high);--cs:var(--high-soft)}
.sv-medium{--c:var(--medium);--cs:var(--medium-soft)}.sv-low{--c:var(--low);--cs:var(--low-soft)}.sv-info{--c:var(--info);--cs:var(--info-soft)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--c);flex:none}
.pill{display:inline-flex;align-items:center;gap:4px;height:22px;padding:0 8px;border-radius:6px;font-size:11.5px;font-weight:650;letter-spacing:.02em;color:var(--c);background:var(--cs);white-space:nowrap}
.pill svg{width:13px;height:13px}
.okp{--c:var(--good);--cs:var(--brand-soft)}

/* top bar */
.topbar{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:saturate(1.4) blur(10px);-webkit-backdrop-filter:saturate(1.4) blur(10px);border-bottom:1px solid var(--line)}
.topbar .in{max-width:1120px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;gap:12px}
.brand{display:flex;align-items:center;gap:9px;font-weight:700;font-size:16px;letter-spacing:-.01em;color:var(--ink);text-decoration:none}
.brand svg{width:24px;height:24px;color:var(--brand)}
.ver{font:500 11.5px var(--mono);color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:1px 6px}
.spacer{flex:1}
.when{font-size:13px;color:var(--muted)}
.icon-btn{display:grid;place-items:center;width:34px;height:34px;border-radius:9px;border:1px solid var(--line);background:var(--surface);cursor:pointer;color:var(--ink-2)}
.icon-btn:hover{border-color:var(--line-2);color:var(--ink)}
.icon-btn svg{width:18px;height:18px}
.icon-btn .sun{display:none}
:root[data-theme="dark"] .icon-btn .sun{display:block}:root[data-theme="dark"] .icon-btn .moon{display:none}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .icon-btn .sun{display:block}:root:not([data-theme="light"]) .icon-btn .moon{display:none}}

/* hero */
.hero{display:grid;grid-template-columns:300px 1fr;gap:20px;margin-top:28px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}
.score-card{padding:26px 22px 22px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;position:relative;overflow:hidden}
.clients{display:flex;flex-wrap:wrap;justify-content:center;gap:6px;position:relative}
.clients span{font-size:12px;font-weight:550;color:var(--ink-2);background:var(--raised);border:1px solid var(--line);border-radius:99px;padding:3px 10px}
.score-card::before{content:"";position:absolute;inset:-40% -20% auto;height:220px;background:radial-gradient(closest-side,var(--tone-soft),transparent);opacity:.9;pointer-events:none}
.tone-good{--tone:var(--good);--tone-soft:color-mix(in srgb,var(--good) 16%,transparent)}
.tone-warn{--tone:var(--warn);--tone-soft:color-mix(in srgb,var(--warn) 18%,transparent)}
.tone-bad{--tone:var(--bad);--tone-soft:color-mix(in srgb,var(--bad) 16%,transparent)}
.gauge{width:230px;height:auto;position:relative}
.g-track{fill:none;stroke:var(--line);stroke-width:14;stroke-linecap:round}
.g-value{fill:none;stroke:var(--tone);stroke-width:14;stroke-linecap:round}
.g-num{font:750 56px var(--sans);letter-spacing:-.04em;fill:var(--ink)}
.g-of{font:500 13px var(--sans);fill:var(--muted)}
.g-grade{font:700 13px var(--sans);letter-spacing:.14em;fill:var(--tone)}
.summary{padding:24px 26px;display:flex;flex-direction:column;gap:18px}
.eyebrow{font-size:12px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:0}
.verdict{margin:6px 0 0;font-size:28px;line-height:1.15;letter-spacing:-.025em;font-weight:750}
.verdict span{color:var(--tone)}
.lede{margin:8px 0 0;color:var(--ink-2);font-size:15.5px;max-width:60ch}
.dist{display:flex;height:10px;border-radius:99px;overflow:hidden;background:var(--line);gap:2px}
.seg{background:var(--c);min-width:6px}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:10px;font-size:13.5px;color:var(--ink-2)}
.lg{display:inline-flex;align-items:center;gap:7px}.lg b{color:var(--ink);font-weight:650}.lg.zero{opacity:.45}
.stats{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--line);margin:0 -26px -24px;}
.stat{padding:14px 26px;border-right:1px solid var(--line)}.stat:last-child{border-right:0}
.stat b{display:block;font-size:22px;letter-spacing:-.02em;font-weight:700}
.stat span{font-size:12.5px;color:var(--muted)}

/* sections */
section{margin-top:44px;scroll-margin-top:72px}
.sec-head{display:flex;align-items:baseline;justify-content:space-between;gap:16px;margin-bottom:14px;flex-wrap:wrap}
h2{font-size:19px;letter-spacing:-.015em;margin:0;font-weight:700}
.sec-head p{margin:0;color:var(--muted);font-size:14px}

/* fixes */
.fixes{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}
.fix{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:16px 18px 16px;box-shadow:var(--shadow);position:relative;display:flex;flex-direction:column}
.fix::before{content:"";position:absolute;left:-1px;top:16px;bottom:16px;width:3px;border-radius:0 3px 3px 0;background:var(--c)}
.fix-top{display:flex;align-items:center;gap:8px}
.rank{width:22px;height:22px;border-radius:6px;display:grid;place-items:center;font-size:12px;font-weight:700;background:var(--raised);border:1px solid var(--line);color:var(--ink-2)}
.gain{margin-left:auto;font:600 12.5px var(--mono);color:var(--good);background:var(--brand-soft);padding:2px 8px;border-radius:6px}
.fix h3{margin:12px 0 4px;font-size:15.5px;letter-spacing:-.01em;line-height:1.35}
.fix p{margin:0;color:var(--ink-2);font-size:14px;flex:1}
.targets{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
.tag{font:500 12px var(--mono);padding:3px 8px;border-radius:6px;background:var(--raised);border:1px solid var(--line);color:var(--ink-2);cursor:pointer}
.tag:hover{border-color:var(--line-2);color:var(--ink)}.tag.more{cursor:default}
.more-fixes{margin-top:14px}
.more-fixes summary{cursor:pointer;color:var(--muted);font-size:14px;list-style:none;display:inline-flex;align-items:center;gap:6px}
.more-fixes summary::-webkit-details-marker{display:none}
.more-fixes summary svg{width:14px;height:14px;transition:transform .15s}
.more-fixes[open] summary svg{transform:rotate(90deg)}
.more-fixes .fixes{margin-top:14px}

/* servers */
.servers{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.server{all:unset;box-sizing:border-box;cursor:pointer;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:14px 15px;display:flex;flex-direction:column;gap:8px;box-shadow:var(--shadow);transition:border-color .12s,transform .12s;min-width:0}
.server:hover{border-color:var(--line-2);transform:translateY(-1px)}
.server.active{border-color:var(--c, var(--good));box-shadow:0 0 0 3px color-mix(in srgb,var(--c, var(--good)) 18%,transparent)}
.server.ok{--c:var(--good)}
.server:focus-visible{outline:2px solid var(--brand);outline-offset:2px}
.s-head{display:flex;align-items:center;justify-content:space-between;gap:8px}
.s-name{font-weight:650;font-size:15px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.s-launch{font-size:12px;color:var(--muted);background:var(--code-bg);border:1px solid var(--line);border-radius:7px;padding:5px 8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block}
.s-meta{display:flex;justify-content:space-between;align-items:center;font-size:12.5px;color:var(--muted);gap:8px}
.s-counts{display:flex;gap:9px}
.mini{display:inline-flex;align-items:center;gap:5px;font-weight:600;color:var(--ink-2)}
.mini.none{font-weight:500;color:var(--muted)}

/* findings toolbar */
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.segmented{display:flex;flex-wrap:wrap;gap:4px;background:var(--surface);border:1px solid var(--line);border-radius:11px;padding:3px}
.seg-btn{display:inline-flex;align-items:center;gap:7px;border:0;background:none;border-radius:8px;padding:6px 11px;font-size:13.5px;color:var(--ink-2);cursor:pointer}
.seg-btn b{font-weight:650;color:var(--muted)}
.seg-btn:hover{background:var(--raised)}
.seg-btn.active{background:var(--ink);color:var(--bg)}.seg-btn.active b{color:inherit;opacity:.7}
.search{flex:1;min-width:200px;display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--line);border-radius:11px;padding:0 12px;height:40px;color:var(--muted)}
.search svg{width:17px;height:17px;flex:none}
.search input{all:unset;flex:1;color:var(--ink);font-size:14px;min-width:0}
.active-filter{display:none;align-items:center;gap:6px;font-size:13px;color:var(--ink-2)}
.active-filter.on{display:inline-flex}
.active-filter button{border:1px solid var(--line);background:var(--surface);border-radius:7px;padding:3px 9px;cursor:pointer;font-size:12.5px}
.count{font-size:13px;color:var(--muted);margin-left:auto}

/* finding rows */
.list{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
.finding{border-top:1px solid var(--line)}
.finding:first-child{border-top:0}
.finding summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:82px minmax(0,1fr) minmax(0,auto) 60px 18px;align-items:center;gap:14px;padding:13px 18px;position:relative}
.finding summary::-webkit-details-marker{display:none}
.finding summary::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--c);opacity:0;transition:opacity .12s}
.finding[open] summary::before,.finding summary:hover::before{opacity:1}
.finding summary:hover{background:var(--raised)}
.finding summary .pill{justify-self:start}
.f-title{font-weight:600;font-size:14.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.f-where{display:flex;gap:8px;font-size:13px;color:var(--muted);white-space:nowrap;overflow:hidden;justify-content:flex-end}
.f-where b{color:var(--ink-2);font:600 12.5px var(--mono)}
.f-id{font:500 12px var(--mono);color:var(--muted);text-align:right}
.chev svg{width:16px;height:16px;color:var(--muted);transition:transform .15s}
.finding[open] .chev svg{transform:rotate(90deg)}
.f-body{padding:2px 18px 20px 114px}
.f-msg{margin:0 0 14px;font-size:15px;color:var(--ink)}
.code{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--code-bg)}
.code-head{display:flex;align-items:center;gap:8px;padding:7px 12px;border-bottom:1px solid var(--line);font:500 12px var(--mono);color:var(--muted);background:var(--raised)}
.code-head svg{width:14px;height:14px;flex:none}
.code-head span:not(.ln){overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.code-head .ln{margin-left:auto;white-space:nowrap}
.code pre{margin:0;padding:8px 0;font-size:12.75px;line-height:1.7;overflow-x:auto}
.row{display:flex;min-width:max-content;padding-right:16px}
.row.hit{background:var(--hit);box-shadow:inset 3px 0 0 var(--hit-line)}
.num{width:44px;flex:none;text-align:right;padding-right:14px;color:var(--tc);user-select:none}
.src{white-space:pre;color:var(--ink-2)}
pre.wrap .row{min-width:0}pre.wrap .src{white-space:pre-wrap;word-break:break-word;padding-left:14px}
.src mark{background:color-mix(in srgb,var(--critical) 22%,transparent);color:var(--ink);border-radius:3px;padding:0 2px;box-shadow:inset 0 -1.5px 0 var(--critical)}
.tk{color:var(--tk)}.ts{color:var(--ts)}.tn{color:var(--tn)}.tc{color:var(--tc)}
.explain{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}
.explain>div{border:1px solid var(--line);border-radius:10px;padding:12px 14px;background:var(--raised)}
.explain .howto{background:var(--brand-soft);border-color:color-mix(in srgb,var(--brand) 25%,var(--line))}
.explain h4{margin:0 0 4px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.explain .howto h4{color:var(--brand)}
.explain p{margin:0;font-size:14px;color:var(--ink-2)}
.loc{margin:12px 0 0;display:flex;gap:10px;flex-wrap:wrap;font:12px var(--mono);color:var(--muted)}
.loc code{background:var(--raised);border:1px solid var(--line);border-radius:6px;padding:1px 6px;overflow-wrap:anywhere}
.empty{padding:40px 20px;text-align:center;color:var(--muted)}
.all-clear{padding:36px 24px;display:flex;gap:16px;align-items:center}
.all-clear .ic{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;background:var(--brand-soft);color:var(--brand)}
.all-clear .ic svg{width:24px;height:24px}
.all-clear h3{margin:0;font-size:17px}.all-clear p{margin:2px 0 0;color:var(--muted)}

/* files */
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:11px 16px;border-top:1px solid var(--line);vertical-align:middle}
thead th{border-top:0;font-size:12px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);background:var(--raised)}
td code{font-size:12.5px;color:var(--ink-2);overflow-wrap:anywhere}
.r{text-align:right;white-space:nowrap;color:var(--muted)}
.client{font-weight:600;white-space:nowrap}
.err{color:var(--warn)}
.table-wrap{overflow-x:auto}

footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--line);display:flex;flex-wrap:wrap;gap:8px 24px;justify-content:space-between;font-size:13px;color:var(--muted)}
footer .brand{font-size:13px;font-weight:600;color:var(--ink-2)}footer .brand svg{width:18px;height:18px}

@media (max-width:860px){
  .hero{grid-template-columns:1fr}
  .stats{grid-template-columns:repeat(2,1fr)}
  .stat:nth-child(2){border-right:0}.stat:nth-child(-n+2){border-bottom:1px solid var(--line)}
  .finding summary{grid-template-columns:auto minmax(0,1fr) 18px;gap:10px}
  .f-where,.f-id{display:none}
  .f-body{padding:0 16px 18px}
  .explain{grid-template-columns:1fr}
  .when{display:none}
}
@media (max-width:520px){
  .wrap-page{padding:0 16px 56px}.topbar .in{padding:10px 16px}
  .summary{padding:20px}.stats{margin:0 -20px -20px}.stat{padding:12px 20px}
  .verdict{font-size:24px}
  .fixes{grid-template-columns:1fr}
}
@media print{
  :root{--bg:#fff}
  .topbar,.toolbar,.icon-btn{display:none!important}
  .card,.fix,.list,.server{box-shadow:none}
  details.finding>.f-body,.more-fixes>.fixes{display:block!important}
  .finding,.fix,.server{break-inside:avoid}
  section{margin-top:28px}
}
</style>
</head>
<body>
<header class="topbar"><div class="in">
  <span class="brand">${LOGO}mcpsafe</span><span class="ver">v${esc(version)}</span>
  <span class="spacer"></span>
  <span class="when">Scanned ${esc(whenText)}</span>
  <button class="icon-btn" id="print" title="Print or save as PDF" aria-label="Print">${ICON.print}</button>
  <button class="icon-btn" id="theme" title="Toggle dark mode" aria-label="Toggle dark mode"><span class="moon">${ICON.moon}</span><span class="sun">${ICON.sun}</span></button>
</div></header>

<main class="wrap-page">
  <div class="hero tone-${tone}">
    <div class="card score-card">${gauge(score.value, score.grade)}<div class="clients">${clients.map((c) => `<span>${esc(c)}</span>`).join('')}</div></div>
    <div class="card summary">
      <div>
        <p class="eyebrow">MCP security report</p>
        <h1 class="verdict"><span>${esc(verdictTitle)}.</span> ${findings.length ? `${plural(findings.length, 'finding')}${serious ? `, ${serious} serious` : ''}.` : 'No findings.'}</h1>
        <p class="lede">${esc(verdictText)}${findings.length ? ` Start with the fixes below.` : ''}</p>
      </div>
      <div>
        <div class="dist" aria-hidden="true">${dist}</div>
        <div class="legend">${legend}</div>
      </div>
      <div class="stats">
        <div class="stat"><b>${configs.length}</b><span>config ${configs.length === 1 ? 'file' : 'files'}</span></div>
        <div class="stat"><b>${servers}</b><span>MCP ${servers === 1 ? 'server' : 'servers'}</span></div>
        <div class="stat"><b>${clients.length}</b><span>${clients.length === 1 ? 'client' : 'clients'}</span></div>
        <div class="stat"><b>${toolsScanned || '–'}</b><span>${toolsScanned ? 'tools inspected' : 'tools (use --connect)'}</span></div>
      </div>
    </div>
  </div>

  ${findings.length ? `
  <section id="fix">
    <div class="sec-head"><h2>Fix these first</h2><p>Ordered by severity, then by how much each fix raises your score.</p></div>
    <ol class="fixes">${topFixes}</ol>
    ${moreFixes ? `<details class="more-fixes"><summary>${ICON.chevron}Show ${plural(rules.length - 6, 'more fix', 'more fixes')}</summary><ol class="fixes">${moreFixes}</ol></details>` : ''}
  </section>` : ''}

  ${allServers.length ? `
  <section id="servers">
    <div class="sec-head"><h2>Servers</h2><p>${plural(allServers.length, 'server')} across ${clients.join(', ')}. Click one to filter the findings.</p></div>
    <div class="servers">${serverCards}</div>
  </section>` : ''}

  <section id="findings">
    <div class="sec-head"><h2>Findings</h2></div>
    ${findings.length ? `
    <div class="toolbar">
      <div class="segmented" role="group" aria-label="Filter by severity">${filterButtons}</div>
      <label class="search">${ICON.search}<input id="q" type="search" placeholder="Search findings, servers, rules" aria-label="Search findings"></label>
    </div>
    <div class="toolbar" style="margin-top:-4px">
      <span class="active-filter" id="sf">Server: <b id="sfn"></b><button type="button" id="sfx">Clear</button></span>
      <span class="count" id="count">${plural(findings.length, 'finding')}</span>
    </div>
    <div class="list" id="list">${findingRows}<div class="empty" id="empty" hidden>No findings match these filters.</div></div>`
    : `<div class="card all-clear"><span class="ic">${ICON.check}</span><div><h3>No issues found</h3><p>Nothing risky was detected in the scanned configs.${toolsScanned ? '' : ' Run with --connect to also inspect tool descriptions.'}</p></div></div>`}
  </section>

  <section id="files">
    <div class="sec-head"><h2>Scanned files</h2><p>${plural(configs.length, 'file')}</p></div>
    <div class="card table-wrap">
      <table><thead><tr><th>Client</th><th>Path</th><th class="r">Servers</th><th class="r">Scope</th></tr></thead>
      <tbody>${fileRows || '<tr><td colspan="4" class="empty">No config files found.</td></tr>'}</tbody></table>
    </div>
  </section>

  <footer>
    <span class="brand">${LOGO}mcpsafe v${esc(version)}</span>
    <span>Secrets are masked. Static checks can't prove a server is safe, so review what you install.</span>
  </footer>
</main>

<script>
(function(){
  var root=document.documentElement;
  try{var t=localStorage.getItem('mcpsafe-theme');if(t)root.setAttribute('data-theme',t);}catch(e){}
  document.getElementById('theme').addEventListener('click',function(){
    var dark=root.getAttribute('data-theme')==='dark'||(!root.getAttribute('data-theme')&&matchMedia('(prefers-color-scheme: dark)').matches);
    var next=dark?'light':'dark';root.setAttribute('data-theme',next);
    try{localStorage.setItem('mcpsafe-theme',next);}catch(e){}
  });
  document.getElementById('print').addEventListener('click',function(){window.print();});
  var list=document.getElementById('list');if(!list)return;
  var rows=[].slice.call(list.querySelectorAll('.finding'));
  var sev='all',server='',q='';
  function apply(){
    var n=0;
    rows.forEach(function(r){
      var ok=(sev==='all'||r.dataset.sev===sev)&&(!server||r.dataset.server===server)&&(!q||r.dataset.search.indexOf(q)>=0);
      r.hidden=!ok;if(ok)n++;
    });
    document.getElementById('count').textContent=n+(n===1?' finding':' findings');
    document.getElementById('empty').hidden=n>0;
    document.getElementById('sf').classList.toggle('on',!!server);
    document.getElementById('sfn').textContent=server;
    document.querySelectorAll('.server').forEach(function(s){s.classList.toggle('active',!!server&&s.dataset.server===server);});
  }
  document.querySelectorAll('.seg-btn').forEach(function(b){b.addEventListener('click',function(){
    document.querySelectorAll('.seg-btn').forEach(function(x){x.classList.remove('active');});b.classList.add('active');sev=b.dataset.filter;apply();
  });});
  document.getElementById('q').addEventListener('input',function(e){q=e.target.value.trim().toLowerCase();apply();});
  function pick(name){server=server===name?'':name;apply();if(server)document.getElementById('findings').scrollIntoView({behavior:'smooth',block:'start'});}
  document.querySelectorAll('[data-server]').forEach(function(el){if(el.classList.contains('finding'))return;el.addEventListener('click',function(){pick(el.dataset.server);});});
  document.getElementById('sfx').addEventListener('click',function(){server='';apply();});
  window.addEventListener('beforeprint',function(){rows.forEach(function(r){r.dataset.wasOpen=r.open;r.open=true;r.hidden=false;});});
  window.addEventListener('afterprint',function(){rows.forEach(function(r){r.open=r.dataset.wasOpen==='true';});apply();});
})();
</script>
</body>
</html>
`;
}
