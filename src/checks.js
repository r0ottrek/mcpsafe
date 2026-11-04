// The checks. Each returns findings: { id, severity, server?, file, jsonPath?, message, evidence? }
import os from 'node:os';
import path from 'node:path';
import { RULES, SEVERITIES } from './rules.js';
import { detectSecret, isPlaceholder, mask, SECRET_PATTERNS } from './secrets.js';
import { effectiveCommand, launchedPackages, parseDockerRun, argsAfterPackage, splitCommandLine } from './packages.js';

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
    serverPath: ctx.server?.jsonPath ?? null,
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

// A URL query parameter whose name says it holds a credential. The name is
// matched as a whole word (after splitting camelCase), so "design",
// "keyboard" or "author" do not count.
const CRED_PARAM = /^(?:.*[_.-])?(?:api[_-]?key|apikey|key|token|secret|password|passwd|pwd|auth|sig|signature|credentials?|access[_-]?(?:token|key)|client[_-]?secret)$/i;
const isCredentialParam = (k) => CRED_PARAM.test(String(k).replace(/([a-z0-9])([A-Z])/g, '$1_$2'));
const isRealCredentialValue = (v) => !!v && v.length >= 8 && !isPlaceholder(v) && !/\{\{.*\}\}/.test(v);

const MASK = '•'.repeat(8);

/**
 * Masks every credential-looking part of a string meant for display (finding
 * messages and evidence): URL userinfo, credential query values, KEY=value
 * and --flag value pairs with credential names, Bearer/Basic values, and
 * anything matching a known token format.
 */
export function maskText(text) {
  if (text == null) return text;
  let s = String(text);
  // scheme://user:password@host and scheme://token@host
  s = s.replace(/(\b[a-z][a-z0-9+.-]*:\/\/)([^@/\s?#'"]+)@/gi, (whole, scheme, info) => {
    const colon = info.indexOf(':');
    if (colon >= 0) return `${scheme}${info.slice(0, colon)}:${MASK}@`;
    if (info.length >= 20 || detectSecret(info, 'token')) return `${scheme}${mask(info)}@`;
    return whole;
  });
  s = s.replace(/([?&])([\w.-]+)=([^&#\s'"]+)/g, (whole, sep, k, v) => (isCredentialParam(k) && !isPlaceholder(v) ? `${sep}${k}=${mask(v)}` : whole));
  // GITHUB_TOKEN=... and --api-key=... (a whole word, so "mcp-server-keycloak==1.0" is left alone)
  s = s.replace(/(^|[\s;&|'"(])(--?)?([A-Za-z_][\w-]*)=([^=\s'"&;|][^\s'"&;|]*)/g, (whole, pre, dash = '', k, v) => (isCredentialParam(k) && !isPlaceholder(v) ? `${pre}${dash}${k}=${mask(v)}` : whole));
  // --api-key <value>
  s = s.replace(/(^|\s)(--?[\w-]+)(\s+)([^\s'"-][^\s'"]*)/g, (whole, pre, flag, sp, v) => (isCredentialParam(flag.replace(/^-+/, '')) && !isPlaceholder(v) ? `${pre}${flag}${sp}${mask(v)}` : whole));
  // x-api-key: <value> (Authorization: Bearer <value> is handled below)
  s = s.replace(/(^|[\s'"])([\w-]+)(\s*:\s*)([^\s'"]{8,})/g, (whole, pre, k, sep, v) => (isCredentialParam(k) && !/^(Bearer|Basic)$/i.test(v) && !isPlaceholder(v) ? `${pre}${k}${sep}${mask(v)}` : whole));
  s = s.replace(/\b(Bearer|Basic)(\s+)([A-Za-z0-9._~+/=-]{8,})/gi, (whole, kind, sp, v) => (isPlaceholder(v) ? whole : `${kind}${sp}${mask(v)}`));
  for (const p of SECRET_PATTERNS) {
    if (/^Database/.test(p.name)) continue; // the userinfo step above already masks the password
    s = s.replace(new RegExp(p.re.source, `${p.re.flags.replace('g', '')}g`), (m) => mask(m));
  }
  return s;
}

// ---- Well-known packages, used for typosquat and capability detection ----
const POPULAR_BY_MANAGER = {
  npm: [
    '@modelcontextprotocol/server-filesystem', '@modelcontextprotocol/server-github', '@modelcontextprotocol/server-memory',
    '@modelcontextprotocol/server-everything', '@modelcontextprotocol/server-sequential-thinking', '@modelcontextprotocol/server-puppeteer',
    '@modelcontextprotocol/server-brave-search', '@modelcontextprotocol/server-postgres', '@modelcontextprotocol/server-slack',
    '@modelcontextprotocol/server-gitlab', '@modelcontextprotocol/server-google-maps', '@modelcontextprotocol/server-redis',
    '@modelcontextprotocol/inspector', '@playwright/mcp', '@upstash/context7-mcp', '@notionhq/notion-mcp-server',
    '@supabase/mcp-server-supabase', '@stripe/mcp', '@sentry/mcp-server', '@cloudflare/mcp-server-cloudflare',
    '@wonderwhy-er/desktop-commander', 'firecrawl-mcp', 'figma-developer-mcp', 'mcp-remote', 'chrome-devtools-mcp',
    '@browserbasehq/mcp-server-browserbase', '@heroku/mcp-server', '@azure/mcp', '@railway/mcp-server',
  ],
  pypi: ['mcp-server-fetch', 'mcp-server-git', 'mcp-server-time', 'mcp-server-sqlite', 'awslabs.core-mcp-server', 'serena'],
  docker: ['ghcr.io/github/github-mcp-server', 'mcp/fetch', 'mcp/filesystem', 'mcp/github', 'mcp/postgres', 'mcp/playwright'],
};
export const POPULAR_PACKAGES = Object.values(POPULAR_BY_MANAGER).flat();

// Real, published packages whose names sit next to a popular one. They are
// different projects, not typosquats.
const KNOWN_DISTINCT = new Set(['mcp-server-gsc', 'mcp-server-ga4', 'mcp-server-gcp', 'mcp-server-kit', 'mcp-server-line', 'mcp-server-sqlite3']);

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

const NAME_SEP = /[-_./@]/;

// The parts of two names that differ, after removing the prefix and suffix
// they share up to a separator: "mcp-server-fecth" vs "mcp-server-fetch"
// gives ["fecth", "fetch"].
function distinctParts(a, b) {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  while (i > 0 && !NAME_SEP.test(a[i - 1])) i--;
  let j = 0;
  while (j < a.length - i && j < b.length - i && a[a.length - 1 - j] === b[b.length - 1 - j]) j++;
  while (j > 0 && !NAME_SEP.test(a[a.length - j])) j--;
  return [a.slice(i, a.length - j), b.slice(i, b.length - j)];
}

function isTransposition(x, y) {
  if (x.length !== y.length) return false;
  const diff = [];
  for (let k = 0; k < x.length; k++) if (x[k] !== y[k]) diff.push(k);
  return diff.length === 2 && diff[1] === diff[0] + 1 && x[diff[0]] === y[diff[1]] && x[diff[1]] === y[diff[0]];
}

// A lookalike: two swapped letters, or a small edit relative to the length of
// the part that tells the names apart. Short parts ("gsc" vs "git") are
// different names unless two letters are swapped, and a trailing number
// ("sqlite3") makes a different package, not a typo.
function looksLikeTypo(n, p) {
  const [x, y] = distinctParts(n, p);
  if (x.replace(/\d+$/, '') === y.replace(/\d+$/, '')) return false;
  const len = Math.max(x.length, y.length);
  if (isTransposition(x, y)) return len >= 3;
  if (len <= 3) return false;
  const d = levenshtein(x, y);
  return d === 1 || (len >= 8 && d === 2);
}

/**
 * @param {string} name package or image name
 * @param {string} [manager] 'npm', 'pypi' or 'docker'; when given, only names from the same registry are compared
 */
export function typosquatOf(name, manager) {
  const n = name.toLowerCase();
  if (POPULAR_PACKAGES.includes(n) || KNOWN_DISTINCT.has(n)) return null;
  const candidates = manager && POPULAR_BY_MANAGER[manager] ? POPULAR_BY_MANAGER[manager] : POPULAR_PACKAGES;
  for (const p of candidates) {
    if (levenshtein(n, p) <= 2 && looksLikeTypo(n, p)) return p;
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

const SHELL_PACKAGES = /(desktop-commander|mcp-shell|shell-mcp|server-shell|shell-server|mcp-server-commands|terminal-mcp|mcp-terminal|server-terminal|cli-mcp-server|mcp-server-shell|iterm-mcp|win-cli-mcp|server-win-cli|claude-code-mcp|terminal[-_]controller|ssh-mcp|mcp-ssh)/i;
const FS_PACKAGES = /(server-filesystem|mcp\/filesystem|filesystem-mcp|mcp-filesystem|desktop-commander)/i;
// A local build of the reference filesystem server, e.g. .../src/filesystem/dist/index.js
const FS_SCRIPT = /\/(server-)?filesystem\//i;
// Bridges that connect a stdio client to a remote server given as an argument.
const BRIDGES = /(^|\/)(mcp-remote|supergateway|mcp-proxy)$/i;
const HOME_VARIABLES = ['~', '$home', '${home}', '%userprofile%', '%homepath%', '${userhome}', '${env:home}', '${env:userprofile}', '$env:userprofile', '$env:home'];

function broadPath(p) {
  const home = os.homedir();
  const s = p.replace(/\\/g, '/').replace(/\/+$/, '') || '/';
  if (['/', '/Users', '/home', '/root', '..'].includes(s) || HOME_VARIABLES.includes(s.toLowerCase())) return true;
  if (/^[A-Za-z]:\/?$/.test(s)) return true; // C:\ or C:
  if (/^[A-Za-z]:\/Users(\/[^/]+)?$/i.test(s)) return true;
  if (/^\/(Users|home)\/[^/]+$/.test(s)) return true;
  if (/^\/mnt\/[a-z](\/Users(\/[^/]+)?)?$/i.test(s)) return true; // a Windows drive or home folder under WSL
  if (s === home.replace(/\\/g, '/')) return true;
  return false;
}

// JSON path of the argument holding `value`, so reports can point at the exact line.
function argPath(s, value) {
  let i = s.args.indexOf(value);
  if (i < 0 && value) i = s.args.findIndex((a) => a.includes(value));
  return i >= 0 ? `${s.jsonPath}.args[${i}]` : s.command ? `${s.jsonPath}.command` : s.jsonPath;
}

// Interpreters whose first positional argument is the script they run, with
// the flags that take a value (skipped), load code (kept) or mean that no
// script file follows (stop).
const INTERPRETERS = {
  node: { code: ['-r', '--require', '--import', '--loader', '--experimental-loader'], stop: ['-e', '--eval', '-p', '--print'] },
  python: { value: ['-X', '-W', '-Q'], stop: ['-m', '-c'] },
  deno: { sub: ['run'], value: ['--config', '-c', '--import-map', '--env-file', '--location', '--lock', '--cert'] },
  bun: { sub: ['run'], code: ['-r', '--preload'], value: ['--cwd', '--env-file', '--config', '-c'], stop: ['-e', '--eval', '-p', '--print'] },
  uv: { sub: ['run'], code: ['--directory', '--project'], value: ['--with', '--with-requirements', '--with-editable', '--python', '-p', '--index', '--index-url', '--extra-index-url', '--env-file', '--extra', '--group', '--package'], stop: ['-m'] },
  sh: { stop: ['-c'], stopRe: /^-[a-z]*c[a-z]*$/ }, // bash -c, bash -lc
  pwsh: { code: ['-File', '-file', '-f'], stop: ['-Command', '-command', '-c', '-EncodedCommand'] },
  java: { code: ['-jar', '-cp', '-classpath', '--class-path'], value: [], stop: [] },
  other: {},
};
const INTERPRETER_OF = {
  node: 'node', nodejs: 'node', tsx: 'node', 'ts-node': 'node', python: 'python', python3: 'python', py: 'python', deno: 'deno', bun: 'bun',
  uv: 'uv', sh: 'sh', bash: 'sh', zsh: 'sh', pwsh: 'pwsh', powershell: 'pwsh', java: 'java', ruby: 'other', perl: 'other', php: 'other',
};

// The script an interpreter runs, plus code loaded through flags such as
// node --require. Data paths later on the command line are not included.
function scriptArgs(base, args) {
  const spec = INTERPRETERS[INTERPRETER_OF[base]];
  if (!spec) return [];
  const out = [];
  let rest = args;
  if (spec.sub && spec.sub.includes(rest[0])) rest = rest.slice(1);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const eq = a.match(/^(--?[\w-]+)=(.*)$/);
    const flag = eq ? eq[1] : a;
    if (spec.stop?.includes(flag) || spec.stopRe?.test(flag)) break;
    if (spec.code?.includes(flag)) { if (eq) out.push(eq[2]); else if (rest[i + 1] != null) out.push(rest[++i]); continue; }
    if (a.startsWith('-')) { if (!eq && spec.value?.includes(a)) i++; continue; }
    out.push(a);
    break;
  }
  return out;
}

// Flags and their values in an argument list: --key=value, --key value, and
// HTTP header arguments such as "Authorization: Bearer <token>".
function secretsInArgs(list) {
  const hits = [];
  list.forEach((a, i) => {
    const eq = a.match(/^--?([\w-]+)=(.+)$/);
    const prevFlag = i > 0 && /^--?[\w-]+$/.test(list[i - 1]) ? list[i - 1].replace(/^-+/, '') : '';
    const [key, value] = eq ? [eq[1], eq[2]] : [prevFlag, a];
    let det = detectSecret(value, key);
    if (!det && !/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      const header = value.match(/^([A-Za-z][\w-]*)\s*:\s*(\S.*)$/);
      if (header) det = detectSecret(header[2].trim(), header[1]);
    }
    if (det) hits.push([i, det]);
  });
  return hits;
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
  // --api-key=xxx, --token xxx, --header "Authorization: Bearer xxx"
  for (const [i, det] of secretsInArgs(s.args)) report(`args[${i}]`, det, `${s.jsonPath}.args[${i}]`);
  // The whole command line written into `command`.
  if (s.command && !s.args.length && /\s/.test(s.command.trim())) {
    const seen = new Set();
    for (const [, det] of secretsInArgs(splitCommandLine(s.command))) {
      if (seen.has(det.match)) continue;
      seen.add(det.match);
      report('command', det, `${s.jsonPath}.command`);
    }
  }
  if (s.url) {
    const det = detectSecret(s.url, '');
    if (det) report('url', det, `${s.jsonPath}.url`);
  }
  return out;
}

// The server URL, plus the remote URL given to a bridge such as mcp-remote.
function serverUrls(s) {
  const out = [];
  if (s.url) {
    const key = ['url', 'serverUrl', 'httpUrl', 'endpoint'].find((k) => s.raw[k] === s.url) || 'url';
    out.push([s.url, `${s.jsonPath}.${key}`]);
  }
  const { base, args } = effectiveCommand(s);
  if (BRIDGES.test(base) || launchedPackages(s).some((p) => BRIDGES.test(p.name))) {
    for (const a of args) {
      const v = (a.match(/^(?:--?[\w-]+=)?(https?:\/\/\S+)$/i) || [])[1];
      if (v && !out.some(([u]) => u === v)) out.push([v, argPath(s, a)]);
    }
  }
  return out;
}

function checkUrl(ctx) {
  const s = ctx.server;
  const out = [];
  for (const [url, jsonPath] of serverUrls(s)) {
    let u;
    try { u = new URL(url); } catch { continue; }
    if (u.protocol === 'http:' && !isLocalHost(u.hostname)) {
      out.push(finding('MCS005', ctx, `Connects to ${u.host} over plain http.`, { evidence: maskText(url.replace(/[?#].*/, '')), jsonPath }));
    }
    for (const [k, v] of u.searchParams) {
      if (isCredentialParam(k) && isRealCredentialValue(v)) {
        out.push(finding('MCS006', ctx, `Query parameter "${k}" carries a credential.`, { evidence: `${k}=${mask(v)}`, jsonPath }));
      }
    }
  }
  return out;
}

function checkPackages(ctx) {
  const s = ctx.server;
  const out = [];
  for (const p of launchedPackages(s)) {
    if (p.kind === 'local') continue;
    // Package specs can carry credentials (git+https://<token>@host/...), so
    // only masked forms go into messages and evidence.
    const spec = maskText(p.spec);
    const name = maskText(p.name);
    if (p.kind === 'git' || p.kind === 'url') {
      if (!p.pinned) out.push(finding('MCS018', ctx, `Launches ${spec} straight from ${p.kind === 'git' ? 'a git repository' : 'a URL'} without a pinned commit.`, { evidence: spec, jsonPath: argPath(s, p.spec) }));
      continue;
    }
    if (p.manager === 'docker') {
      if (!p.pinned) out.push(finding('MCS004', ctx, p.version ? `Image ${spec} uses the mutable :latest tag.` : `Image ${spec} has no tag, so it resolves to :latest.`, { evidence: spec, jsonPath: argPath(s, p.spec) }));
    } else if (!p.pinned) {
      out.push(finding('MCS003', ctx,
        p.version ? `${name} is requested as "${maskText(p.version)}", which is not an exact version.` : `${name} runs whatever version is newest on ${p.manager} at launch.`,
        { evidence: spec, jsonPath: argPath(s, p.spec) }));
    }
    const squat = typosquatOf(p.name, p.manager);
    if (squat) out.push(finding('MCS013', ctx, `"${name}" is very close to the popular package "${squat}".`, { evidence: name, jsonPath: argPath(s, p.spec) }));
  }
  return out;
}

// Coding agents that can run as an MCP server and then expose their own
// shell and file tools: `claude mcp serve`, `codex mcp-server`.
function agentServer(base, args, pkgs) {
  let agent = ['claude', 'codex'].includes(base) ? base : null;
  let rest = args;
  const pkg = pkgs[0];
  if (!agent && pkg && /^@anthropic-ai\/claude-code$/i.test(pkg.name)) agent = 'claude';
  if (!agent && pkg && /^@openai\/codex$/i.test(pkg.name)) agent = 'codex';
  if (!agent) return null;
  if (pkg && !['claude', 'codex'].includes(base)) rest = args.slice(args.indexOf(pkg.spec) + 1);
  const words = rest.filter((a) => !a.startsWith('-'));
  const i = words.indexOf('mcp');
  if (agent === 'claude' && i >= 0 && words[i + 1] === 'serve') return 'Claude Code running as an MCP server exposes its Bash, file editing and other built-in tools.';
  if (agent === 'codex' && (words.includes('mcp-server') || (i >= 0 && (words[i + 1] === undefined || words[i + 1] === 'serve')))) return 'Codex running as an MCP server runs an agent that can execute shell commands.';
  return null;
}

function checkShell(ctx) {
  const s = ctx.server;
  const { base, args } = effectiveCommand(s);
  const joined = [s.command, ...s.args].filter(Boolean).join(' ');
  const shown = maskText(joined).slice(0, 160);
  const out = [];
  // MCS010: curl | sh
  if (/(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*(iex|invoke-expression)\b|(ba)?sh\s+<\(\s*curl/i.test(joined)) {
    out.push(finding('MCS010', ctx, 'The launch command pipes a downloaded script into a shell.', { evidence: shown }));
  }
  const pkgs = launchedPackages(s);
  const name = [s.name, ...pkgs.map((p) => p.name)].join(' ');
  const agent = agentServer(base, args, pkgs);
  if (SHELL_PACKAGES.test(name) || (pkgs.length === 0 && /\b(shell|terminal)\b/i.test(s.name))) {
    out.push(finding('MCS007', ctx, `"${maskText(pkgs[0]?.name || s.name)}" exposes shell / command execution tools.`, { evidence: maskText(pkgs[0]?.spec || s.name), jsonPath: pkgs[0] ? argPath(s, pkgs[0].spec) : s.jsonPath }));
  } else if (agent) {
    out.push(finding('MCS007', ctx, agent, { evidence: shown, jsonPath: s.command ? `${s.jsonPath}.command` : s.jsonPath }));
  } else if (['bash', 'sh', 'zsh', 'powershell', 'pwsh'].includes(base) && args.some((a) => /^(-c|-command|-Command)$/i.test(a))) {
    // Inline shell script as the launcher is worth a look, but it is not a shell tool by itself.
    out.push(finding('MCS007', ctx, 'Server is launched through an inline shell script, which hides what actually runs.', { severity: 'low', evidence: shown }));
  }
  return out;
}

function checkFilesystem(ctx) {
  const s = ctx.server;
  const out = [];
  const pkgs = launchedPackages(s);
  const { base, args } = effectiveCommand(s);
  // For a server run from a local build (node .../filesystem/dist/index.js),
  // the script itself is not an allowed directory.
  const scripts = pkgs.length ? [] : scriptArgs(base, args);
  const isFs = FS_PACKAGES.test([s.name, ...pkgs.map((p) => p.name)].join(' '))
    || /^filesystem$/i.test(s.name)
    || scripts.some((a) => FS_SCRIPT.test(a.replace(/\\/g, '/')));
  if (isFs) {
    const roots = argsAfterPackage(s).filter((a) => !/^[a-z]+:\/\//.test(a) && !scripts.includes(a));
    const broad = roots.filter(broadPath);
    if (broad.length) out.push(finding('MCS008', ctx, `Allowed directories include ${broad.map((b) => `"${b}"`).join(', ')}.`, { evidence: broad.join(' '), jsonPath: argPath(s, broad[0]) }));
  }
  // Docker volume mounts of / or home
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

const TEMP_DIR = /^(\/tmp|\/var\/tmp|\/private\/tmp|\/dev\/shm)(\/|$)|\/Downloads(\/|$)|\/AppData\/Local\/Temp(\/|$)/i;

// Only the code that runs is checked: the program, the working folder, the
// script given to an interpreter and local package paths. Output folders,
// databases, filesystem roots and container mounts are data, not code.
function checkLocation(ctx) {
  const s = ctx.server;
  const { cmd, base, args } = effectiveCommand(s);
  const candidates = [
    [cmd, s.command === cmd ? `${s.jsonPath}.command` : null],
    [s.cwd, `${s.jsonPath}.cwd`],
    ...scriptArgs(base, args).map((a) => [a, null]),
    ...launchedPackages(s).filter((p) => p.kind === 'local').map((p) => [p.spec, null]),
  ].filter(([c]) => c);
  const hit = candidates.find(([c]) => TEMP_DIR.test(String(c).replace(/\\/g, '/')));
  if (!hit) return [];
  const [value, jsonPath] = hit;
  return [finding('MCS014', ctx, `Runs code from ${maskText(value)}.`, { evidence: maskText(value), jsonPath: jsonPath || argPath(s, value) })];
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
    // mcp__<server> approves every tool of that server; tool rules are
    // mcp__<server>__<tool>, so a server name may itself contain "_".
    const broad = mcp.filter((a) => /^mcp__(?:(?!__).)*(__\*)?$/.test(a) || a.includes('*'));
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

export const POISON = [
  [/<\s*(important|system|instructions?|secret|hidden|admin)\b[^>]*>/i, 'hidden tag'],
  [/\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier|other)\s+(instructions|prompts|rules)/i, 'instruction override'],
  [/\b(do not|don't|never|must not)\s+(tell|mention|inform|reveal|notify|show|alert)\b[^.]{0,40}\buser\b/i, 'asks the model to hide something from the user'],
  [/\b(before|prior to)\s+(using|calling|invoking)\s+(this|any|the)\s+tool\b[^.]{0,80}\b(read|cat|open|fetch|send|pass|include)\b/i, 'pre-call side task'],
  [/(~\/|\$HOME\/|%USERPROFILE%)?\.(ssh|aws|gnupg|kube|docker)\b|id_rsa|id_ed25519|\.env\b|credentials\.json|claude_desktop_config|\.cursor\/mcp\.json|mcp\.json|\/etc\/passwd|private[_ ]key/i, 'references sensitive files'],
  [/\b(send|post|upload|forward|exfiltrate|transmit)\b[^.]{0,60}\b(to|via)\b[^.]{0,40}(https?:\/\/|@[\w-]+\.\w+|webhook)/i, 'sends data to an external destination'],
  [/\b(pass|include|put|add)\s+(its|the|their|all)\s+(contents?|content)\b[^.]{0,40}\b(as|in|into)\b[^.]{0,30}\b(parameters?|param|arguments?|field|sidenote|note)/i, 'smuggles data through a parameter'],
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
        out.push(finding('MCS016', ctx, `Tool "${t.name}": ${reasons.join(', ')}.`, { severity: severe ? 'critical' : 'medium', evidence: full.replace(/[ \t]+/g, ' ').trim().slice(0, 1200), jsonPath: `tools.${t.name}` }));
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
