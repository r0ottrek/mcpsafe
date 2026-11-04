// Renders docs/social-preview.png (1280x640) for the GitHub repo settings.
// Usage: node scripts/demo/social.mjs
import { createRequire } from 'node:module';
import { big } from '../../src/report/terminal.js';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const logo = big('mcpsafe').join('\n');
const html = `<!doctype html><meta charset="utf-8"><style>
body{margin:0;width:1280px;height:640px;background:#141414;color:#d4d4d4;font-family:'DejaVu Sans Mono',Menlo,monospace}
.wrap{padding:150px 120px 0}
pre{margin:0;font:inherit;white-space:pre}
.logo{font-size:64px;line-height:64px;color:#6fb3b8}
.tag{font-size:34px;line-height:44px;margin-top:44px}
.cmd{font-size:26px;line-height:36px;margin-top:56px;color:#8a8a8a}
.cmd b{font-weight:normal;color:#d4d4d4}
</style><div class="wrap"><pre class="logo">${logo}</pre>
<div class="tag">security audit for MCP servers</div>
<div class="cmd">$ <b>npx github:r0ottrek/mcpsafe</b></div></div>`;

const browser = await chromium.launch();
const pg = await browser.newPage({ viewport: { width: 1280, height: 640 } });
await pg.setContent(html);
await pg.screenshot({ path: new URL('../../docs/social-preview.png', import.meta.url).pathname });
await browser.close();
console.log('wrote docs/social-preview.png');
