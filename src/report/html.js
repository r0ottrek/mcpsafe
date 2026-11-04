// Self-contained HTML report. It is laid out like a printed audit document:
// one column of typeset text, tables and rules, no cards or decoration.
// No network requests, so it can be opened offline and shared as one file.
import { RULES, SEVERITIES } from '../rules.js';
import { displayPath, POISON } from '../checks.js';
import { configSecrets, snippet } from '../locate.js';
import { maskArgv, maskString } from '../mask.js';
import { impactByRule } from '../score.js';
import { launchedPackages, effectiveCommand } from '../packages.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
// The text a reader sees in a fragment of this report's own markup (escaped
// text and closed tags only), for the search box. Line numbers are left out.
export const visibleText = (html) => html.replace(/<span class="no">\d+<\/span>/g, ' ').replace(/<[^<>]*>/g, ' ')
  .replace(/&(amp|lt|gt|quot|#39);/g, (_, e) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" }[e])).replace(/\s+/g, ' ');
const cap = (s) => s[0].toUpperCase() + s.slice(1);
const NUMBER_WORDS = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten'];
const words = (n) => NUMBER_WORDS[n] ?? String(n);

const VERDICT = {
  A: 'Nothing serious stands out in this setup.',
  B: 'A few small things are worth tightening up.',
  C: 'Some settings make it easier for a bad server or a malicious prompt to cause damage.',
  D: 'Several settings put your files, credentials or machine at risk.',
  F: 'This setup exposes credentials or lets untrusted code act on the machine.',
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

// Mask credentials in a command line or other free text. The masking is
// shared with every report: see src/mask.js.
export function maskCommand(text, known = null) {
  return maskString(String(text ?? ''), { known });
}

// What a server runs, for the Servers table. Masked before it is shortened,
// so a cut cannot leave part of a secret behind.
function launcher(s, known) {
  let text;
  if (s.url) {
    try { const u = new URL(s.url); text = `${u.protocol.replace(':', '')}://${u.host}${u.pathname === '/' ? '' : u.pathname}`; } catch { text = s.url; }
  } else {
    const pkg = launchedPackages(s)[0];
    const { base } = effectiveCommand(s);
    // Argument by argument, so that a value after a --flag is recognised.
    text = pkg ? maskCommand(`${base} ${pkg.spec}`, known) : maskArgv([s.command, ...s.args].filter(Boolean), { known }).join(' ');
  }
  const chars = [...(s.url ? maskCommand(text, known) : text)];
  return chars.length > 80 ? `${chars.slice(0, 79).join('')}…` : chars.join('');
}

// Findings are filtered by server, or by file for findings that belong to a
// file and not to one server (for example settings that apply to every server).
const baseName = (p) => String(displayPath(p) || '').split(/[\\/]/).pop();
const filterKey = (f) => (f.server ? `server:${f.server}` : `file:${displayPath(f.file) || ''}`);
const filterLabel = (f) => f.server || baseName(f.file) || 'unknown';

// A 0-100 ruler with the grade bands marked and the score pointed out.
function scale(value, grade) {
  const bands = [['F', 0, 60], ['D', 60, 70], ['C', 70, 80], ['B', 80, 90], ['A', 90, 100]];
  const W = 640;
  const x = (v) => (v / 100) * W;
  const parts = bands.map(([g, a, b]) => `
      <rect x="${x(a) + (a ? 1 : 0)}" y="22" width="${x(b) - x(a) - (a ? 1 : 0)}" height="8" class="${g === grade ? 'band on' : 'band'}"/>
      <text x="${(x(a) + x(b)) / 2}" y="46" text-anchor="middle" class="${g === grade ? 'bl on' : 'bl'}">${g}</text>`).join('');
  const ticks = [0, 60, 70, 80, 90, 100].map((v) => `<text x="${Math.min(Math.max(x(v), 6), W - 8)}" y="62" text-anchor="middle" class="tick">${v}</text>`).join('');
  const mx = Math.min(Math.max(x(value), 1), W - 1);
  return `<svg class="scale" viewBox="-8 0 ${W + 16} 66" role="img" aria-label="Score ${value} on a 0 to 100 scale, grade ${grade}">
    ${parts}
    <line x1="${mx}" x2="${mx}" y1="12" y2="34" class="marker"/>
    <text x="${Math.min(Math.max(mx, 14), W - 14)}" y="9" text-anchor="middle" class="ml">${value}</text>
    ${ticks}
  </svg>`;
}

export function renderHtml(result) {
  const { score, findings, configs, servers, toolsScanned, generatedAt, version, live } = result;
  // Config files that could not be read or parsed; the CLI lists them in result.errors.
  const errors = result.errors ?? configs.filter((c) => c.error).map((c) => ({ path: c.source.path, error: c.error }));
  const incomplete = errors.length > 0;
  const incompleteText = `The scan is incomplete: ${plural(errors.length, 'config file')} could not be read or parsed, so this score covers only the files that were read.`;
  const allServers = configs.flatMap((c) => c.servers);
  const clients = [...new Set(configs.map((c) => c.source.client))];
  const impact = impactByRule(findings);
  const textOf = Object.fromEntries(configs.map((c) => [c.source.path, c.text]));
  const when = new Date(generatedAt).toLocaleString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' });

  // ---- summary sentence ----
  const countWords = SEVERITIES.filter((s) => score.counts[s]).map((s) => `${score.counts[s]} ${s}`);
  const listText = countWords.length > 1 ? `${countWords.slice(0, -1).join(', ')} and ${countWords.at(-1)}` : countWords[0];
  const verdict = incomplete ? incompleteText : VERDICT[score.grade];
  const summary = findings.length
    ? `${cap(words(findings.length))} finding${findings.length === 1 ? '' : 's'}: ${listText}. ${verdict}`
    : `No findings. ${verdict}`;

  // ---- what to fix first: one row per rule ----
  const byRule = new Map();
  for (const f of findings) {
    if (!byRule.has(f.id)) byRule.set(f.id, { id: f.id, sev: f.severity, targets: new Map(), n: 0 });
    const r = byRule.get(f.id);
    r.n++;
    r.targets.set(filterKey(f), f);
    if (SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(r.sev)) r.sev = f.severity;
  }
  const rules = [...byRule.values()].sort((a, b) => SEVERITIES.indexOf(a.sev) - SEVERITIES.indexOf(b.sev) || impact[b.id] - impact[a.id]);
  const fixRows = rules.map((r, i) => `
        <tr>
          <td class="n">${i + 1}</td>
          <td><strong>${esc(RULES[r.id].title)}</strong><br><span class="fixtext">${esc(RULES[r.id].fix)}</span></td>
          <td>${[...r.targets].map(([key, f]) => `<button type="button" class="link" data-key="${esc(key)}" data-label="${esc(f.server ? `server ${f.server}` : `file ${displayPath(f.file) || ''}`)}"${f.server ? '' : ` title="${esc(displayPath(f.file))}"`}>${esc(filterLabel(f))}</button>`).join(', ')}</td>
          <td><span class="sev s-${r.sev}">${cap(r.sev)}</span></td>
          <td class="num">${impact[r.id] > 0 ? `+${impact[r.id]}` : '0'}</td>
        </tr>`).join('');

  // ---- servers ----
  const serverRows = allServers.map((s) => {
    const fs = findings.filter((f) => f.server === s.name && f.file === s.file);
    const counts = SEVERITIES.filter((sev) => fs.some((f) => f.severity === sev))
      .map((sev) => `<span class="s-${sev}">${fs.filter((f) => f.severity === sev).length} ${sev}</span>`).join(', ');
    return `
        <tr>
          <td>${fs.length ? `<button type="button" class="link strong" data-key="${esc(`server:${s.name}`)}" data-label="${esc(`server ${s.name}`)}">${esc(s.name)}</button>` : `<strong>${esc(s.name)}</strong>`}</td>
          <td>${esc(s.client)}${s.scope === 'project' ? ' (project)' : ''}${s.disabled ? ', disabled' : ''}</td>
          <td><code>${esc(launcher(s, configSecrets(textOf[s.file])))}</code></td>
          <td>${counts || '<span class="muted">None</span>'}</td>
        </tr>`;
  }).join('');

  // ---- findings ----
  const findingBlocks = findings.map((f, i) => {
    const isTool = !!(f.jsonPath && f.jsonPath.startsWith('tools.'));
    const snip = isTool ? null : snippet(textOf[f.file], f.line);
    let excerpt = '';
    if (snip) {
      excerpt = `<pre class="excerpt" aria-label="Excerpt from ${esc(displayPath(f.file))}">${snip.map((l) => `<span class="${l.hit ? 'ln hit' : 'ln'}"><span class="no">${l.n}</span>${esc(l.text) || ' '}</span>`).join('')}</pre>`;
    } else if (f.evidence) {
      excerpt = `<p class="label">${isTool ? `Description of tool <code>${esc(f.jsonPath.slice(6))}</code>, as the model sees it` : 'Evidence'}</p><pre class="excerpt wrap">${f.id === 'MCS016' ? markPoison(f.evidence) : esc(maskCommand(f.evidence, configSecrets(textOf[f.file])))}</pre>`;
    }
    const where = [
      f.server ? ['Server', `${esc(f.server)}${f.client ? ` in ${esc(f.client)}` : ''}`] : f.client ? ['Client', esc(f.client)] : null,
      f.file ? ['File', `<code>${esc(displayPath(f.file))}${f.line ? `:${f.line}` : ''}</code>`] : null,
      f.jsonPath && !f.jsonPath.startsWith('tools.') ? ['Key', `<code>${esc(f.jsonPath)}</code>`] : null,
    ].filter(Boolean).map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('');
    const search = [f.id, f.title, f.server, f.client, f.message, displayPath(f.file), visibleText(excerpt)].join(' ').toLowerCase();
    return `
      <article class="finding" id="f${i + 1}" data-sev="${f.severity}" data-key="${esc(filterKey(f))}" data-search="${esc(search)}">
        <p class="kicker"><span class="sev s-${f.severity}">${cap(f.severity)}</span> <span class="rid">${esc(f.id)}</span></p>
        <h3>${esc(f.title)}</h3>
        <p class="msg">${esc(f.message)}</p>
        <dl class="where">${where}</dl>
        ${excerpt}
        <p><strong>Why it matters.</strong> ${esc(RULES[f.id].why)}</p>
        <p><strong>Fix.</strong> ${esc(f.fix)}</p>
      </article>`;
  }).join('');

  const filterLinks = [`<button type="button" class="flt on" data-filter="all">All (${findings.length})</button>`,
    ...SEVERITIES.filter((s) => score.counts[s]).map((s) => `<button type="button" class="flt" data-filter="${s}">${cap(s)} (${score.counts[s]})</button>`)].join('');

  const fileRows = configs.map((c) => `
        <tr>
          <td>${esc(c.source.client)}</td>
          <td><code>${esc(displayPath(c.source.path))}</code></td>
          <td>${c.source.scope === 'project' ? 'Project' : 'User'}</td>
          <td class="num">${c.error ? `<span class="s-medium">${esc(c.error)}</span>` : c.servers.length}</td>
        </tr>`).join('');

  const notChecked = [];
  if (!toolsScanned) notChecked.push('Tool descriptions were not inspected, so hidden instructions (MCS016) and tool shadowing (MCS017) could not be checked. Run again with <code>--connect</code> to start each server and read its tools.');
  if (live && result.liveErrors?.length) notChecked.push(`Tools could not be listed for ${result.liveErrors.map((e) => `<code>${esc(e.server)}</code> (${esc(e.error)})`).join(', ')}.`);
  notChecked.push('Static checks read configuration only. They cannot tell whether the code a server runs is safe.');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>mcpsafe report, ${esc(when)}</title>
<style>
:root{
  --paper:#ffffff;--ink:#1d1d1b;--ink-2:#45443f;--muted:#6f6d66;--rule:#d8d6cf;--rule-2:#bdbab1;--shade:#f4f3ef;
  --hl:#fde68a;--hl-ink:#1d1d1b;--link:#1f4e8c;
  --critical:#9f1d1d;--high:#b4441a;--medium:#7c5a00;--low:#33518a;--info:#6f6d66;
  --serif:Charter,"Bitstream Charter","Sitka Text",Cambria,Georgia,serif;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){:root{
  --paper:#181816;--ink:#e6e4dd;--ink-2:#c9c6bd;--muted:#99968c;--rule:#36352f;--rule-2:#4a4840;--shade:#21201d;
  --hl:#5c4a12;--hl-ink:#f3eedd;--link:#8fb3e8;
  --critical:#f08a7e;--high:#f0a072;--medium:#dcc06a;--low:#9bb5e6;--info:#99968c;
}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:17px/1.6 var(--serif);font-variant-numeric:oldstyle-nums}
main{max-width:52rem;margin:0 auto;padding:3rem 1.25rem 4rem}
h1,h2,h3{font-weight:700;line-height:1.25;margin:0}
h1{font-size:2rem;letter-spacing:-.01em}
h2{font-size:1.3rem;margin:3rem 0 .9rem;padding-top:.9rem;border-top:2px solid var(--ink)}
h3{font-size:1.1rem;margin:.15rem 0 .35rem}
p{margin:.6rem 0}
code,pre{font-family:var(--mono);font-size:.8em;font-variant-numeric:normal}
td code{overflow-wrap:anywhere}
.muted{color:var(--muted)}
.num{text-align:right;font-variant-numeric:lining-nums tabular-nums;white-space:nowrap}

.s-critical{color:var(--critical)}.s-high{color:var(--high)}.s-medium{color:var(--medium)}.s-low{color:var(--low)}.s-info{color:var(--info)}
.sev{font-weight:700}

/* masthead */
.mast{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;flex-wrap:wrap;font-size:.95rem;color:var(--muted);padding-bottom:.6rem;border-bottom:1px solid var(--rule);margin-bottom:2.2rem}
.mast b{color:var(--ink);font-weight:700}
.mast .act{display:flex;gap:1.1rem}

.lead{font-size:1.15rem;color:var(--ink-2);max-width:40rem;margin-top:.8rem}
.scale{display:block;width:100%;max-width:40rem;height:auto;margin:1.6rem 0 .4rem;font-family:var(--serif)}
.band{fill:var(--rule)}.band.on{fill:var(--ink)}
.bl{font-size:13px;fill:var(--muted)}.bl.on{fill:var(--ink);font-weight:700}
.tick{font-size:11px;fill:var(--muted);font-variant-numeric:lining-nums}
.marker{stroke:var(--ink);stroke-width:2}
.ml{font-size:13px;font-weight:700;fill:var(--ink);font-variant-numeric:lining-nums}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:.15rem 1.5rem;margin:1.4rem 0 0;font-size:.95rem}
.facts dt{color:var(--muted)}.facts dd{margin:0}

/* tables */
table{width:100%;border-collapse:collapse;font-size:.92rem;margin:.4rem 0}
th{text-align:left;font-weight:700;padding:.45rem .7rem .45rem 0;border-bottom:1px solid var(--ink);vertical-align:bottom}
td{padding:.6rem .7rem .6rem 0;border-bottom:1px solid var(--rule);vertical-align:top}
th:last-child,td:last-child{padding-right:0}
td.n{color:var(--muted);width:1.6rem;font-variant-numeric:lining-nums}
.fixtext{color:var(--ink-2)}
.wide{overflow-x:auto}

button.link{all:unset;cursor:pointer;color:var(--link);text-decoration:underline;text-decoration-thickness:1px;text-underline-offset:2px}
button.link:hover{text-decoration-thickness:2px}
button.link.strong{font-weight:700}
button.link:focus-visible,.flt:focus-visible{outline:2px solid var(--link);outline-offset:2px}
a{color:var(--link)}

/* findings */
.controls{display:flex;flex-wrap:wrap;align-items:baseline;gap:.4rem 1.1rem;margin:.2rem 0 1rem;font-size:.95rem}
.controls .lab{color:var(--muted)}
.flt{all:unset;cursor:pointer;color:var(--link)}
.flt.on{color:var(--ink);font-weight:700;text-decoration:underline;text-underline-offset:3px}
.controls input{font:inherit;font-size:.95rem;color:var(--ink);background:transparent;border:0;border-bottom:1px solid var(--rule-2);padding:.15rem 0;min-width:14rem;flex:1}
.controls input:focus{outline:none;border-bottom-color:var(--ink)}
.status{font-size:.9rem;color:var(--muted);margin:0 0 .5rem}
.serverflt{display:none}.serverflt.on{display:inline}
.finding{padding:1.3rem 0 1.1rem;border-bottom:1px solid var(--rule)}
.finding:first-of-type{border-top:1px solid var(--rule)}
.kicker{margin:0;font-size:.9rem}
.rid{font-family:var(--mono);font-size:.78rem;color:var(--muted);margin-left:.35rem}
.msg{font-size:1.02rem;margin:.2rem 0 .7rem}
.where{display:grid;grid-template-columns:max-content 1fr;gap:.1rem 1.1rem;font-size:.9rem;margin:0 0 .9rem}
.where dt{color:var(--muted)}.where dd{margin:0;min-width:0;overflow-wrap:anywhere}
.label{font-size:.88rem;color:var(--muted);margin:.4rem 0 .3rem}
.excerpt{background:var(--shade);border:1px solid var(--rule);padding:.55rem 0;margin:.4rem 0 1rem;overflow-x:auto;line-height:1.65;font-size:.8rem}
.excerpt .ln{display:block;padding:0 .9rem 0 0;white-space:pre;min-width:max-content}
.excerpt .no{display:inline-block;width:3.2em;padding-right:1em;text-align:right;color:var(--muted);user-select:none}
.excerpt .hit{background:var(--hl);color:var(--hl-ink)}
.excerpt .hit .no{color:inherit;font-weight:700}
.excerpt.wrap{white-space:pre-wrap;word-break:break-word;padding:.6rem .9rem}
mark{background:var(--hl);color:var(--hl-ink);padding:0 1px}
.none{padding:1rem 0;color:var(--muted)}
.warn{color:var(--medium);border-left:3px solid var(--medium);padding-left:.8rem}

ul.scope{padding-left:1.2rem}ul.scope li{margin:.3rem 0}
footer{margin-top:3.5rem;padding-top:.8rem;border-top:1px solid var(--rule);font-size:.88rem;color:var(--muted)}

@media (max-width:640px){
  body{font-size:16px}
  main{padding:1.6rem 1rem 3rem}
  h1{font-size:1.6rem}
  .hide-sm{display:none}
  table{font-size:.88rem}
}
@media print{
  body{font-size:11pt}
  main{max-width:none;padding:0}
  .act,.controls,.status{display:none!important}
  .finding{display:block!important;break-inside:avoid}
  h2{break-after:avoid}
  button.link{color:inherit;text-decoration:none}
}
</style>
</head>
<body>
<main>
  <div class="mast">
    <span><b>mcpsafe</b> ${esc(version)} &nbsp;MCP configuration audit</span>
    <span class="act"><span>${esc(when)}</span><button type="button" class="link" id="print">Print</button></span>
  </div>

  <h1>Score ${score.value} of 100, grade ${score.grade}</h1>
  <p class="lead">${esc(summary)}</p>
  ${incomplete ? `<p class="warn"><strong>Incomplete scan.</strong> ${plural(errors.length, 'config file')} could not be read or parsed. A file that could not be read may hold problems this report does not show.</p>` : ''}
  ${scale(score.value, score.grade)}
  <dl class="facts">
    <dt>Scanned</dt><dd>${configs.length || !toolsScanned ? `${plural(configs.length, 'config file')} containing ${plural(servers, 'MCP server')}` : `No config files. ${plural(toolsScanned, 'tool description')} from a tools file.`}</dd>
    ${incomplete ? `<dt>Incomplete</dt><dd class="s-medium">${esc(errors.map((e) => displayPath(e.path)).join(', '))}</dd>` : ''}
    <dt>Clients</dt><dd>${clients.length ? esc(clients.join(', ')) : 'None found'}</dd>
    <dt>Tool descriptions</dt><dd>${toolsScanned ? `${toolsScanned} inspected` : 'Not inspected (run with <code>--connect</code>)'}</dd>
  </dl>

  ${rules.length ? `
  <h2>What to fix first</h2>
  <p class="muted">One line per problem, most severe first. Points show how much the score rises once every instance is fixed.</p>
  <div class="wide"><table>
    <thead><tr><th></th><th>Problem and fix</th><th>Where</th><th>Severity</th><th class="num">Points</th></tr></thead>
    <tbody>${fixRows}</tbody>
  </table></div>` : ''}

  ${allServers.length ? `
  <h2>Servers</h2>
  <div class="wide"><table>
    <thead><tr><th>Name</th><th>Client</th><th>Runs</th><th>Findings</th></tr></thead>
    <tbody>${serverRows}</tbody>
  </table></div>` : ''}

  <h2 id="findings">Findings</h2>
  ${findings.length ? `
  <div class="controls">
    <span class="lab">Show</span>${filterLinks}
    <input id="q" type="search" placeholder="Search" aria-label="Search findings">
  </div>
  <p class="status"><span id="count">${plural(findings.length, 'finding')}</span><span class="serverflt" id="sf"> for <b id="sfn"></b>. <button type="button" class="link" id="sfx">Show all</button></span></p>
  ${findingBlocks}
  <p class="none" id="empty" hidden>No findings match.</p>` : '<p>No findings.</p>'}

  <h2>Scope</h2>
  <div class="wide"><table>
    <thead><tr><th>Client</th><th>File</th><th>Scope</th><th class="num">Servers</th></tr></thead>
    <tbody>${fileRows || '<tr><td colspan="4" class="muted">No config files found.</td></tr>'}</tbody>
  </table></div>
  <ul class="scope">${notChecked.map((t) => `<li>${t}</li>`).join('')}</ul>

  <footer>Generated by mcpsafe ${esc(version)}. Credentials in this report are masked.</footer>
</main>
<script>
(function(){
  document.getElementById('print').addEventListener('click',function(){window.print();});
  var items=[].slice.call(document.querySelectorAll('.finding'));if(!items.length)return;
  var sev='all',key='',label='',q='';
  function apply(){
    var n=0;
    items.forEach(function(r){var ok=(sev==='all'||r.dataset.sev===sev)&&(!key||r.dataset.key===key)&&(!q||r.dataset.search.indexOf(q)>=0);r.hidden=!ok;if(ok)n++;});
    document.getElementById('count').textContent=n+(n===1?' finding':' findings');
    document.getElementById('empty').hidden=n>0;
    document.getElementById('sf').classList.toggle('on',!!key);
    document.getElementById('sfn').textContent=label;
  }
  document.querySelectorAll('.flt').forEach(function(b){b.addEventListener('click',function(){
    document.querySelectorAll('.flt').forEach(function(x){x.classList.remove('on');});b.classList.add('on');sev=b.dataset.filter;apply();});});
  document.getElementById('q').addEventListener('input',function(e){q=e.target.value.trim().toLowerCase();apply();});
  document.querySelectorAll('button[data-key]').forEach(function(el){el.addEventListener('click',function(){
    key=el.dataset.key;label=el.dataset.label;apply();document.getElementById('findings').scrollIntoView({behavior:'smooth'});});});
  document.getElementById('sfx').addEventListener('click',function(){key='';label='';apply();});
  window.addEventListener('beforeprint',function(){items.forEach(function(r){r.hidden=false;});});
  window.addEventListener('afterprint',apply);
})();
</script>
</body>
</html>
`;
}
