// Renders a terminal session to an animated GIF (needs Playwright + ffmpeg).
// Usage: node render-gif.mjs <ansi-output-file> <out.gif> [command]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const [ansiFile, outGif, command = 'npx mcpsafe'] = process.argv.slice(2);
const ROWS = 40;
const COLS = 100;

const COLORS = { 31: '#e0605a', 32: '#8fb35f', 33: '#d9a94a', 34: '#6b93d6', 35: '#b48ead', 36: '#6fb3b8', 90: '#8a8a8a', 97: '#ffffff', 30: '#111' };
const BG = { 41: '#e03131', 42: '#2f9e44', 43: '#f59f00' };
const esc = (s) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

// Style state carries across lines, like a real terminal.
const st = { bold: false, dim: false, fg: null, bg: null };
function ansiToHtml(line) {
  let out = '';
  const span = (t) => {
    if (!t) return '';
    const css = [];
    if (st.bold) css.push('font-weight:700');
    if (st.dim) css.push('opacity:.6');
    if (st.fg) css.push(`color:${st.fg}`);
    if (st.bg) css.push(`background:${st.bg}`);
    return css.length ? `<span style="${css.join(';')}">${esc(t)}</span>` : esc(t);
  };
  const parts = line.split(/\x1b\[([0-9;]*)m/);
  for (let i = 0; i < parts.length; i++) {
    if (i % 2 === 0) { out += span(parts[i]); continue; }
    for (const code of parts[i].split(';').map(Number)) {
      if (code === 0) Object.assign(st, { bold: false, dim: false, fg: null, bg: null });
      else if (code === 1) st.bold = true;
      else if (code === 2) st.dim = true;
      else if (code === 22) { st.bold = false; st.dim = false; }
      else if (code === 39) st.fg = null;
      else if (code === 49) st.bg = null;
      else if (COLORS[code]) st.fg = COLORS[code];
      else if (BG[code]) st.bg = BG[code];
    }
  }
  return out || '&nbsp;';
}

const output = fs.readFileSync(ansiFile, 'utf8').replace(/\n+$/, '').split('\n');
const prompt = '<span style="color:#9a9a9a">~/code/my-app $</span> ';

// Build frames: [htmlLines, durationMs]
const frames = [];
const screen = (lines) => lines.slice(-ROWS);
for (let i = 0; i <= command.length; i++) {
  frames.push([[`${prompt}${esc(command.slice(0, i))}<span class="cur">█</span>`], i === 0 ? 700 : 70]);
}
frames.push([[`${prompt}${esc(command)}`], 450]);
const shown = [`${prompt}${esc(command)}`];
const html = output.map(ansiToHtml);
let i = 0;
const CHUNK = 3;
while (i < html.length) {
  shown.push(...html.slice(i, i + CHUNK));
  i += CHUNK;
  // Pause on the score line so it can be read.
  const pause = output.slice(i - CHUNK, i).some((l) => /Score/.test(l)) ? 1800 : 110;
  frames.push([screen(shown), pause]);
}
frames.push([screen([...shown, `${prompt}<span class="cur">█</span>`]), 4500]);

const page = (lines) => `<!doctype html><html><head><style>
body{margin:0;background:transparent;font-family:'DejaVu Sans Mono',Menlo,monospace}
.win{width:${COLS * 8.45 + 32}px;background:#141414;border-radius:4px;overflow:hidden;box-shadow:0 0 0 1px #2c2f36}
.bar{height:32px;background:#1d2026;display:flex;align-items:center;gap:8px;padding:0 13px;position:relative;border-bottom:1px solid #262a31}
.bar b{position:absolute;left:0;right:0;text-align:center;font:500 12.5px 'Inter',sans-serif;color:#8a929e;pointer-events:none}
.bar i{width:12px;height:12px;border-radius:50%;display:block}
.term{padding:12px 16px 14px;color:#d4d4d4;font-size:14px;line-height:17px;height:${ROWS * 17}px;white-space:pre;overflow:hidden}
.cur{color:#adb5bd}
</style></head><body><div class="win"><div class="term">${lines.join('\n')}</div></div></body></html>`;

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcpsafe-gif-'));
const browser = await chromium.launch();
const p = await browser.newPage({ viewport: { width: 940, height: 640 }, deviceScaleFactor: 1 });
const list = [];
for (let f = 0; f < frames.length; f++) {
  await p.setContent(page(frames[f][0]));
  const file = path.join(tmp, `f${String(f).padStart(4, '0')}.png`);
  await p.locator('.win').screenshot({ path: file });
  list.push(`file '${file}'\nduration ${(frames[f][1] / 1000).toFixed(3)}`);
}
await browser.close();
list.push(`file '${path.join(tmp, `f${String(frames.length - 1).padStart(4, '0')}.png`)}'`);
fs.writeFileSync(path.join(tmp, 'list.txt'), list.join('\n'));
execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', path.join(tmp, 'list.txt'),
  '-vf', 'split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle', '-loop', '0', outGif]);
console.log(`wrote ${outGif} (${frames.length} frames, ${(fs.statSync(outGif).size / 1024).toFixed(0)} KB)`);
