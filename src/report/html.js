import { RULES } from '../rules.js';
import { displayPath } from '../checks.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

export function renderHtml(result) {
  const { score, findings, configs, servers, toolsScanned, generatedAt, version } = result;
  const gradeClass = { A: 'good', B: 'good', C: 'warn', D: 'warn', F: 'bad' }[score.grade];
  const dash = 2 * Math.PI * 52;
  const offset = dash * (1 - score.value / 100);

  const byRule = new Map();
  for (const f of findings) {
    if (!byRule.has(f.id)) byRule.set(f.id, { sev: f.severity, targets: new Set() });
    byRule.get(f.id).targets.add(f.server || displayPath(f.file));
  }

  const counts = Object.entries(score.counts)
    .map(([s, n]) => `<button class="chip sev-${s}" data-filter="${s}" ${n ? '' : 'disabled'}><b>${n}</b> ${s}</button>`).join('');

  const findingCards = findings.map((f) => `
    <article class="finding" data-sev="${f.severity}">
      <div class="f-head">
        <span class="sev sev-${f.severity}">${f.severity}</span>
        <span class="rule">${esc(f.id)}</span>
        <h3>${esc(f.title)}</h3>
      </div>
      <p class="where">${f.server ? `<span class="srv">${esc(f.server)}</span>` : ''}${f.client ? `<span>${esc(f.client)}</span>` : ''}<code>${esc(displayPath(f.file))}</code>${f.jsonPath ? `<code class="jp">${esc(f.jsonPath)}</code>` : ''}</p>
      <p>${esc(f.message)}</p>
      ${f.evidence ? `<pre>${esc(f.evidence)}</pre>` : ''}
      <details><summary>Why it matters and how to fix it</summary><p>${esc(RULES[f.id].why)}</p><p class="fix"><b>Fix:</b> ${esc(f.fix)}</p></details>
    </article>`).join('');

  const fixList = [...byRule].map(([id, r]) => `
    <li><span class="sev sev-${r.sev}">${r.sev}</span> <b>${esc(RULES[id].title)}</b>
      <span class="muted">(${esc([...r.targets].join(', '))})</span><br>${esc(RULES[id].fix)}</li>`).join('');

  const files = configs.map((c) => `<li><code>${esc(displayPath(c.source.path))}</code> <span class="muted">${esc(c.source.client)} · ${c.error ? esc(c.error) : `${c.servers.length} server${c.servers.length === 1 ? '' : 's'}`}</span></li>`).join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcpsafe report</title>
<style>
:root{--bg:#f7f7f5;--card:#fff;--text:#1b1b1f;--muted:#6b6b76;--line:#e4e4e0;--code:#f0f0ec;
--critical:#b4232a;--high:#d9480f;--medium:#b7791f;--low:#2b6cb0;--info:#6b6b76;--good:#2f855a;--warn:#b7791f;--bad:#b4232a}
@media (prefers-color-scheme:dark){:root{--bg:#121214;--card:#1b1b1f;--text:#ececf1;--muted:#9a9aa6;--line:#2c2c33;--code:#24242a;
--critical:#ff6b6b;--high:#ff922b;--medium:#fcc419;--low:#74c0fc;--good:#69db7c;--warn:#fcc419;--bad:#ff6b6b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px 64px}
header{display:flex;gap:28px;align-items:center;flex-wrap:wrap;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:24px}
.ring{position:relative;width:128px;height:128px;flex:none}
.ring svg{transform:rotate(-90deg)}
.ring .num{position:absolute;inset:0;display:grid;place-items:center;text-align:center}
.ring .num b{font-size:34px;line-height:1}.ring .num span{display:block;font-size:13px;color:var(--muted)}
.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}
h1{margin:0 0 4px;font-size:22px}h2{font-size:17px;margin:36px 0 12px}h3{margin:0;font-size:15px}
.muted{color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.chip{border:1px solid var(--line);background:var(--bg);color:var(--text);border-radius:999px;padding:4px 12px;font:inherit;font-size:13px;cursor:pointer}
.chip[disabled]{opacity:.4;cursor:default}.chip:not([disabled]) b{color:var(--sevc)}.chip.active{outline:2px solid currentColor}
.finding{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--sevc);border-radius:10px;padding:14px 16px;margin:10px 0}
.f-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.sev{--c:var(--sevc);display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--sevc);border:1px solid var(--sevc);border-radius:4px;padding:0 6px}
.sev-critical{--sevc:var(--critical)}.sev-high{--sevc:var(--high)}.sev-medium{--sevc:var(--medium)}.sev-low{--sevc:var(--low)}.sev-info{--sevc:var(--info)}
.finding[data-sev=critical]{--sevc:var(--critical)}.finding[data-sev=high]{--sevc:var(--high)}.finding[data-sev=medium]{--sevc:var(--medium)}.finding[data-sev=low]{--sevc:var(--low)}.finding[data-sev=info]{--sevc:var(--info)}
.rule{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted)}
.where{display:flex;flex-wrap:wrap;gap:6px 12px;font-size:13px;color:var(--muted);margin:8px 0}
.srv{color:var(--text);font-weight:600}
code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;background:var(--code);border-radius:5px}
code{padding:1px 6px;overflow-wrap:anywhere}pre{padding:8px 10px;white-space:pre-wrap;word-break:break-all;margin:8px 0}
.jp{opacity:.8}
details summary{cursor:pointer;color:var(--muted);font-size:13px}
.fix b{color:var(--good)}
ol.fixes{padding-left:22px}ol.fixes li{margin:0 0 12px}
ul.files{padding-left:18px;font-size:14px}
footer{margin-top:48px;font-size:13px;color:var(--muted)}
</style>
</head>
<body>
<main>
<header>
  <div class="ring ${gradeClass}">
    <svg width="128" height="128" viewBox="0 0 128 128" aria-hidden="true">
      <circle cx="64" cy="64" r="52" fill="none" stroke="var(--line)" stroke-width="12"/>
      <circle cx="64" cy="64" r="52" fill="none" stroke="currentColor" stroke-width="12" stroke-linecap="round" stroke-dasharray="${dash.toFixed(1)}" stroke-dashoffset="${offset.toFixed(1)}"/>
    </svg>
    <div class="num"><div><b>${score.value}</b><span>grade ${score.grade}</span></div></div>
  </div>
  <div>
    <h1>MCP security report</h1>
    <div class="muted">${configs.length} config file${configs.length === 1 ? '' : 's'} · ${servers} server${servers === 1 ? '' : 's'}${toolsScanned ? ` · ${toolsScanned} tools` : ''} · ${esc(new Date(generatedAt).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }))}</div>
    <div class="chips">${counts}</div>
  </div>
</header>

${findings.length ? `<h2>Fix list</h2><ol class="fixes">${fixList}</ol>
<h2>Findings</h2>${findingCards}` : '<h2>No issues found</h2><p class="muted">Nothing risky was detected in the scanned configs.</p>'}

<h2>Scanned files</h2>
<ul class="files">${files || '<li class="muted">No config files found.</li>'}</ul>

<footer>Generated by mcpsafe ${esc(version)}. Secrets are masked in this report. Static checks cannot prove a server is safe; review what you install.</footer>
</main>
<script>
document.querySelectorAll('.chip[data-filter]').forEach(function(b){b.addEventListener('click',function(){
  var on=!b.classList.contains('active');document.querySelectorAll('.chip').forEach(function(x){x.classList.remove('active')});
  if(on)b.classList.add('active');
  document.querySelectorAll('.finding').forEach(function(f){f.style.display=!on||f.dataset.sev===b.dataset.filter?'':'none'});
})});
</script>
</body>
</html>
`;
}
