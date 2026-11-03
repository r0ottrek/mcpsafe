// The checks. Each returns findings: { id, severity, server?, file, jsonPath?, message, evidence? }
import os from 'node:os';
import path from 'node:path';
import { RULES, SEVERITIES } from './rules.js';
import { detectSecret, mask } from './secrets.js';
import { effectiveCommand, launchedPackages, parseDockerRun, argsAfterPackage } from './packages.js';

const INVISIBLE = /[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]|[\u{E0000}-\u{E007F}]/gu;

function finding(id, ctx, message, extra = {}) {
  return {
    id,
    title: RULES[id].title,
    severity: extra.severity || RULES[id].severity,
    server: ctx.server?.name ?? null,
    client: ctx.server?.client ?? ctx.config?.source.client ?? null,
    file: ctx.server?.file ?? ctx.config?.source.path ?? null,
    jsonPath: extra.jsonPath ?? ctx.server?.jsonPath ?? null,
    message,
    evidence: extra.evidence ?? null,
    fix: RULES[id].fix,
  };
}

function downgrade(sev) {
  const i = SEVERITIES.indexOf(sev);
  return SEVERITIES[Math.min(i + 1, SEVERITIES.length - 1)];
}

const isLocalHost = (h) => /^(localhost|127(\.\d+){3}|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal)$/i.test(h);

// ---- Well-known packages, used for typosquat and capability detection ----
export const POPULAR_PACKAGES = [
  '@modelcontextprotocol/server-filesystem', '@modelcontextprotocol/server-github', '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-everything', '@modelcontextprotocol/server-sequential-thinking', '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-brave-search', '@modelcontextprotocol/server-postgres', '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-gitlab', '@modelcontextprotocol/server-google-maps', '@modelcontextprotocol/server-redis',
  '@modelcontextprotocol/inspector', '@playwright/mcp', '@upstash/context7-mcp', '@notionhq/notion-mcp-server',
  '@supabase/mcp-server-supabase', '@stripe/mcp', '@sentry/mcp-server', '@cloudflare/mcp-server-cloudflare',
  '@wonderwhy-er/desktop-commander', 'firecrawl-mcp', 'figma-developer-mcp', 'mcp-remote', 'chrome-devtools-mcp',
  '@browserbasehq/mcp-server-browserbase', '@heroku/mcp-server', '@azure/mcp', '@railway/mcp-server',
  'mcp-server-fetch', 'mcp-server-git', 'mcp-server-time', 'mcp-server-sqlite', 'awslabs.core-mcp-server', 'serena',
  'ghcr.io/github/github-mcp-server', 'mcp/fetch', 'mcp/filesystem', 'mcp/github', 'mcp/postgres', 'mcp/playwright',
];

export function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return 99;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

export function typosquatOf(name) {
  const n = name.toLowerCase();
  if (POPULAR_PACKAGES.includes(n)) return null;
  for (const p of POPULAR_PACKAGES) {
    const d = levenshtein(n, p);
    if (d > 0 && d <= (p.length > 12 ? 2 : 1)) return p;
    // Same package name under a different / missing scope, e.g. "modelcontextprotocol-server-github"
    const bare = p.replace(/^@[^/]+\//, '');
    if (p.startsWith('@') && n !== p && (n === p.slice(1) || n === p.slice(1).replace('/', '-'))) return p;
    if (p.startsWith('@modelcontextprotocol/') && n.endsWith(`/${bare}`) && !n.startsWith('@modelcontextprotocol/')) {
      const scope = n.split('/')[0];
      if (levenshtein(scope, '@modelcontextprotocol') <= 3) return p;
    }
  }
  return null;
}

const SHELL_PACKAGES = /(desktop-commander|mcp-shell|shell-mcp|server-shell|shell-server|mcp-server-commands|terminal-mcp|mcp-terminal|server-terminal|cli-mcp-server|mcp-server-shell|iterm-mcp|win-cli-mcp|ssh-mcp|mcp-ssh)/i;
const FS_PACKAGES = /(server-filesystem|mcp\/filesystem|filesystem-mcp|mcp-filesystem|desktop-commander)/i;

function broadPath(p) {
  const home = os.homedir();
  const s = p.replace(/\\/g, '/').replace(/\/+$/, '') || '/';
  if (['/', '~', '$HOME', '${HOME}', '%USERPROFILE%', '/Users', '/home', '/root', '..'].includes(s)) return true;
  if (/^[A-Za-z]:\/?$/.test(s)) return true; // C:\ or C:
  if (/^[A-Za-z]:\/Users(\/[^/]+)?$/i.test(s)) return true;
  if (/^\/(Users|home)\/[^/]+$/.test(s)) return true;
  if (s === home.replace(/\\/g, '/')) return true;
  return false;
}

// ---------------- Server-level checks ----------------

function checkSecrets(ctx) {
  const s = ctx.server;
  const out = [];
  const project = s.scope === 'project';
  const report = (where, det, jsonPath) => {
    let severity = det.confidence === 'high' ? 'high' : 'medium';
    if (project) severity = 'critical';
    out.push(finding('MCS001', ctx,
      `${det.type} found in ${where}${project ? '. This is a project file that is likely committed to git' : ''}.`,
      { severity, evidence: mask(det.match), jsonPath }));
  };
  for (const [k, v] of Object.entries(s.env)) {
    const det = detectSecret(v, k);
    if (det) report(`env.${k}`, det, `${s.jsonPath}.env.${k}`);
  }
  for (const [k, v] of Object.entries(s.headers)) {
    const det = detectSecret(v, k);
    if (det) report(`headers.${k}`, det, `${s.jsonPath}.headers.${k}`);
  }
  s.args.forEach((a, i) => {
    // --api-key=xxx or --token xxx
    const eq = a.match(/^--?([\w-]+)=(.+)$/);
    const prevFlag = i > 0 && /^--?[\w-]+$/.test(s.args[i - 1]) ? s.args[i - 1].replace(/^-+/, '') : '';
    const det = eq ? detectSecret(eq[2], eq[1]) : detectSecret(a, prevFlag);
    if (det) report(`args[${i}]`, det, `${s.jsonPath}.args[${i}]`);
  });
  if (s.url) {
    const det = detectSecret(s.url, '');
    if (det) report('url', det, `${s.jsonPath}.url`);
  }
  return out;
}

function checkUrl(ctx) {
  const s = ctx.server;
  const out = [];
  if (!s.url) return out;
  let u;
  try { u = new URL(s.url); } catch { return out; }
  if (u.protocol === 'http:' && !isLocalHost(u.hostname)) {
    out.push(finding('MCS005', ctx, `Connects to ${u.host} over plain http.`, { evidence: s.url.replace(/\?.*/, '') }));
  }
  for (const [k, v] of u.searchParams) {
    if (/(key|token|secret|auth|password|sig|access)/i.test(k) && v && !/\$\{/.test(v)) {
      out.push(finding('MCS006', ctx, `Query parameter "${k}" carries a credential.`, { evidence: `${k}=${mask(v)}` }));
    }
  }
  return out;
}

function checkPackages(ctx) {
  const s = ctx.server;
  const out = [];
  for (const p of launchedPackages(s)) {
    if (p.kind === 'local') continue;
    if (p.kind === 'git' || p.kind === 'url') {
      if (!p.pinned) out.push(finding('MCS018', ctx, `Launches ${p.spec} straight from ${p.kind === 'git' ? 'a git repository' : 'a URL'} without a pinned commit.`, { evidence: p.spec }));
      continue;
    }
    if (p.manager === 'docker') {
      if (!p.pinned) out.push(finding('MCS004', ctx, p.version ? `Image ${p.spec} uses the mutable :latest tag.` : `Image ${p.spec} has no tag, so it resolves to :latest.`, { evidence: p.spec }));
    } else if (!p.pinned) {
      out.push(finding('MCS003', ctx,
        p.version ? `${p.name} is requested as "${p.version}", which is not an exact version.` : `${p.name} runs whatever version is newest on ${p.manager} at launch.`,
        { evidence: p.spec }));
    }
    const squat = typosquatOf(p.name);
    if (squat) out.push(finding('MCS013', ctx, `"${p.name}" is very close to the popular package "${squat}".`, { evidence: p.name }));
  }
  return out;
}

function checkShell(ctx) {
  const s = ctx.server;
  const { base, args } = effectiveCommand(s);
  const joined = [s.command, ...s.args].filter(Boolean).join(' ');
  const out = [];
  // MCS010: curl | sh
  if (/(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*(iex|invoke-expression)\b|(ba)?sh\s+<\(\s*curl/i.test(joined)) {
    out.push(finding('MCS010', ctx, 'The launch command pipes a downloaded script into a shell.', { evidence: joined.slice(0, 160) }));
  }
  const pkgs = launchedPackages(s);
  const name = [s.name, ...pkgs.map((p) => p.name)].join(' ');
  if (SHELL_PACKAGES.test(name) || (pkgs.length === 0 && /\b(shell|terminal)\b/i.test(s.name))) {
    out.push(finding('MCS007', ctx, `"${pkgs[0]?.name || s.name}" exposes shell / command execution tools.`, { evidence: pkgs[0]?.spec || s.name }));
  } else if (['bash', 'sh', 'zsh', 'powershell', 'pwsh'].includes(base) && args.some((a) => /^(-c|-command|-Command)$/i.test(a))) {
    // Inline shell script as the launcher is worth a look, but it is not a shell tool by itself.
    out.push(finding('MCS007', ctx, 'Server is launched through an inline shell script, which hides what actually runs.', { severity: 'low', evidence: joined.slice(0, 160) }));
  }
  return out;
}

function checkFilesystem(ctx) {
  const s = ctx.server;
  const out = [];
  const pkgs = launchedPackages(s);
  const isFs = FS_PACKAGES.test([s.name, ...pkgs.map((p) => p.name)].join(' '));
  if (isFs) {
    const roots = argsAfterPackage(s).filter((a) => !/^[a-z]+:\/\//.test(a));
    const broad = roots.filter(broadPath);
    if (broad.length) out.push(finding('MCS008', ctx, `Allowed directories include ${broad.map((b) => `"${b}"`).join(', ')}.`, { evidence: broad.join(' ') }));
  }
  // Docker volume mounts of / or home
  const { base, args } = effectiveCommand(s);
  if (['docker', 'podman'].includes(base)) {
    const d = parseDockerRun(args);
    for (const [flag, val] of d?.flags || []) {
      if (typeof val !== 'string') continue;
      let src = null;
      if (flag === '-v' || flag === '--volume') src = val.split(':').slice(0, /^[A-Za-z]:/.test(val) ? 2 : 1).join(':');
      if (flag === '--mount') src = (val.match(/(?:source|src)=([^,]+)/) || [])[1];
      if (src && broadPath(src)) out.push(finding('MCS008', ctx, `Container mounts "${src}" from the host.`, { evidence: `${flag} ${val}` }));
    }
  }
  return out;
}

function checkDocker(ctx) {
  const s = ctx.server;
  const { base, args } = effectiveCommand(s);
  if (!['docker', 'podman'].includes(base)) return [];
  const d = parseDockerRun(args);
  if (!d) return [];
  const bad = [];
  for (const [flag, val] of d.flags) {
    if (flag === '--privileged') bad.push('--privileged');
    if ((flag === '--network' || flag === '--net') && val === 'host') bad.push('--network host');
    if (flag === '--pid' && val === 'host') bad.push('--pid host');
    if (flag === '--ipc' && val === 'host') bad.push('--ipc host');
    if (flag === '--cap-add' && /^(ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE|DAC_READ_SEARCH)$/i.test(String(val))) bad.push(`--cap-add ${val}`);
    if (flag === '--security-opt' && /(apparmor|seccomp)[=:]unconfined/i.test(String(val))) bad.push(`--security-opt ${val}`);
    if (typeof val === 'string' && /docker\.sock/.test(val)) bad.push(`${flag} ${val}`);
  }
  return bad.length ? [finding('MCS009', ctx, `Container is started with ${bad.join(', ')}.`, { evidence: bad.join(' ') })] : [];
}

function checkAutoApprove(ctx) {
  const s = ctx.server;
  const out = [];
  if (s.autoApprove.length) {
    const wildcard = s.autoApprove.some((t) => t === '*' || t === true);
    out.push(finding('MCS011', ctx, `${s.autoApprove.length} tool(s) run without asking: ${s.autoApprove.slice(0, 5).join(', ')}${s.autoApprove.length > 5 ? ', …' : ''}.`,
      { severity: wildcard ? 'high' : 'medium', evidence: s.autoApprove.join(', '), jsonPath: `${s.jsonPath}.${s.raw.autoApprove ? 'autoApprove' : 'alwaysAllow'}` }));
  }
  if (s.trust) out.push(finding('MCS011', ctx, '"trust": true skips confirmation for every tool on this server.', { severity: 'high', jsonPath: `${s.jsonPath}.trust` }));
  return out;
}

function checkLocation(ctx) {
  const s = ctx.server;
  const candidates = [s.command, s.cwd, ...s.args].filter(Boolean).map((x) => String(x).replace(/\\/g, '/'));
  const hit = candidates.find((c) => /^(\/tmp\/|\/var\/tmp\/|\/private\/tmp\/|\/dev\/shm\/)|\/Downloads\/|\/AppData\/Local\/Temp\//i.test(c));
  return hit ? [finding('MCS014', ctx, `Runs code from ${hit}.`, { evidence: hit })] : [];
}

export const SERVER_CHECKS = [checkSecrets, checkUrl, checkPackages, checkShell, checkFilesystem, checkDocker, checkAutoApprove, checkLocation];

// ---------------- File-level checks ----------------

function checkFileUnicode(ctx) {
  const t = ctx.config.text || '';
  const body = t.charCodeAt(0) === 0xfeff ? t.slice(1) : t;
  const hits = [...body.matchAll(INVISIBLE)];
  if (!hits.length) return [];
  const line = body.slice(0, hits[0].index).split('\n').length;
  const codes = [...new Set(hits.map((h) => `U+${h[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`))];
  return [finding('MCS015', ctx, `${hits.length} invisible character(s) found, first on line ${line}.`, { evidence: codes.join(', ') })];
}

function checkFilePermissions(ctx, serverFindings) {
  // Project files normally live in a repo with default permissions; this check is for files in your home folder.
  if (process.platform === 'win32' || ctx.config.mode == null || ctx.config.source.scope !== 'user') return [];
  const hasSecret = serverFindings.some((f) => f.id === 'MCS001' && f.file === ctx.config.source.path);
  if (!hasSecret || (ctx.config.mode & 0o044) === 0) return [];
  return [finding('MCS002', ctx, `File mode is ${ctx.config.mode.toString(8).padStart(3, '0')}; other users can read the secrets in it.`, { evidence: `mode ${ctx.config.mode.toString(8)}` })];
}

function checkClientSettings(ctx) {
  const doc = ctx.config.doc;
  const out = [];
  if (!doc || typeof doc !== 'object') return out;
  // Claude Code: enableAllProjectMcpServers
  const scan = (obj, prefix) => {
    if (obj?.enableAllProjectMcpServers === true) {
      out.push(finding('MCS012', ctx, 'Every server in any project\'s .mcp.json starts without asking.', { jsonPath: `${prefix}enableAllProjectMcpServers` }));
    }
  };
  scan(doc, '');
  if (doc.projects) for (const [p, cfg] of Object.entries(doc.projects)) scan(cfg, `projects["${p}"].`);
  // Claude Code: permissions.allow with mcp__ entries
  const allow = doc.permissions?.allow;
  if (Array.isArray(allow)) {
    const mcp = allow.filter((a) => typeof a === 'string' && /^mcp__/.test(a));
    const broad = mcp.filter((a) => /^mcp__[^_]+(__\*)?$/.test(a) || a.includes('*'));
    if (broad.length) {
      out.push(finding('MCS011', ctx, `Every tool from ${broad.length} MCP server(s) is pre-approved: ${broad.slice(0, 5).join(', ')}.`,
        { severity: broad.some((b) => b === 'mcp__*' || b === 'mcp__') ? 'high' : 'medium', jsonPath: 'permissions.allow', evidence: broad.join(', ') }));
    }
  }
  // Claude Code: bypass permissions as default mode
  if (doc.permissions?.defaultMode === 'bypassPermissions') {
    out.push(finding('MCS011', ctx, 'defaultMode is "bypassPermissions": every tool call, including MCP tools, runs without asking.', { severity: 'high', jsonPath: 'permissions.defaultMode' }));
  }
  // VS Code / Cursor global auto-approve
  for (const key of ['chat.tools.autoApprove', 'chat.tools.global.autoApprove']) {
    if (doc[key] === true) out.push(finding('MCS011', ctx, `"${key}": true lets the agent run every tool without confirmation.`, { severity: 'high', jsonPath: key }));
  }
  return out;
}

// ---------------- Tool-level checks (live mode / tools file) ----------------

const POISON = [
  [/<\s*(important|system|instructions?|secret|hidden|admin)\b[^>]*>/i, 'hidden tag'],
  [/\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier|other)\s+(instructions|prompts|rules)/i, 'instruction override'],
  [/\b(do not|don't|never|must not)\s+(tell|mention|inform|reveal|notify|show|alert)\b[^.]{0,40}\buser\b/i, 'asks the model to hide something from the user'],
  [/\b(before|prior to)\s+(using|calling|invoking)\s+(this|any|the)\s+tool\b[^.]{0,80}\b(read|cat|open|fetch|send|pass|include)\b/i, 'pre-call side task'],
  [/(~\/|\$HOME\/|%USERPROFILE%)?\.(ssh|aws|gnupg|kube|docker)\b|id_rsa|id_ed25519|\.env\b|credentials\.json|claude_desktop_config|\.cursor\/mcp\.json|mcp\.json|\/etc\/passwd|private[_ ]key/i, 'references sensitive files'],
  [/\b(send|post|upload|forward|exfiltrate|transmit)\b[^.]{0,60}\b(to|via)\b[^.]{0,40}(https?:\/\/|@[\w-]+\.\w+|webhook)/i, 'sends data to an external destination'],
  [/\b(pass|include|put|add)\s+(its|the|their|all)\s+(contents?|content)\b[^.]{0,40}\b(as|in|into)\b[^.]{0,30}\b(param|parameter|argument|field|sidenote|note)/i, 'smuggles data through a parameter'],
];

export function analyzeDescription(text) {
  const reasons = [];
  if (!text) return reasons;
  for (const [re, label] of POISON) if (re.test(text)) reasons.push(label);
  if (new RegExp(INVISIBLE.source, 'u').test(text)) reasons.push('invisible Unicode characters');
  if (/[A-Za-z0-9+/]{120,}={0,2}/.test(text)) reasons.push('long encoded blob');
  return reasons;
}

/** @param {{server: string, tools: {name: string, description?: string, inputSchema?: any}[]}[]} toolSets */
export function checkTools(toolSets, serverByName = {}) {
  const out = [];
  const owner = new Map();
  const allNames = new Set();
  for (const set of toolSets) for (const t of set.tools) allNames.add(t.name);

  for (const set of toolSets) {
    const srv = serverByName[set.server] || { name: set.server, client: null, file: set.file || null, jsonPath: null };
    const ctx = { server: srv };
    for (const t of set.tools) {
      // Collect description text from the tool and every parameter description.
      const texts = [t.description || ''];
      const walk = (schema) => {
        if (!schema || typeof schema !== 'object') return;
        if (typeof schema.description === 'string') texts.push(schema.description);
        if (typeof schema.title === 'string') texts.push(schema.title);
        for (const v of Object.values(schema.properties || {})) walk(v);
        if (schema.items) walk(schema.items);
      };
      walk(t.inputSchema);
      const full = texts.join('\n');
      const reasons = analyzeDescription(full);
      if (reasons.length) {
        const severe = reasons.some((r) => r !== 'references sensitive files' && r !== 'long encoded blob') || reasons.length >= 2;
        out.push(finding('MCS016', ctx, `Tool "${t.name}": ${reasons.join(', ')}.`, { severity: severe ? 'critical' : 'medium', evidence: full.replace(/\s+/g, ' ').slice(0, 200), jsonPath: `tools.${t.name}` }));
      }
      // Shadowing: same tool name on multiple servers
      if (owner.has(t.name) && owner.get(t.name) !== set.server) {
        out.push(finding('MCS017', ctx, `Tool "${t.name}" is also provided by "${owner.get(t.name)}". The model cannot tell them apart.`, { evidence: t.name }));
      } else owner.set(t.name, set.server);
      // Cross-server references: description talks about another server's tool
      const own = new Set(set.tools.map((x) => x.name));
      for (const other of allNames) {
        if (own.has(other) || other.length < 5) continue;
        if (new RegExp(`\\b${other.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(full)) {
          out.push(finding('MCS017', ctx, `Tool "${t.name}" gives instructions about "${other}", a tool from another server.`, { evidence: other }));
        }
      }
    }
  }
  return out;
}

// ---------------- Runner ----------------

export function runChecks(configs) {
  const findings = [];
  for (const config of configs) {
    const fileFindings = [];
    for (const server of config.servers) {
      const ctx = { server, config };
      for (const check of SERVER_CHECKS) {
        for (const f of check(ctx)) {
          if (server.disabled && f.id !== 'MCS001') { f.severity = downgrade(f.severity); f.message += ' (server is disabled)'; }
          fileFindings.push(f);
        }
      }
    }
    const ctx = { config };
    fileFindings.push(...checkFileUnicode(ctx), ...checkClientSettings(ctx));
    fileFindings.push(...checkFilePermissions(ctx, fileFindings));
    findings.push(...fileFindings);
  }
  return findings;
}

export function displayPath(p) {
  if (!p) return p;
  const cwd = process.cwd();
  if (p.startsWith(cwd + path.sep)) return path.relative(cwd, p);
  const home = os.homedir();
  return p.startsWith(home + path.sep) ? `~${p.slice(home.length)}` : p;
}
