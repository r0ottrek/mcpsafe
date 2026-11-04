// The checks. Each returns findings: { id, severity, server?, file, jsonPath?, message, evidence? }
import os from 'node:os';
import path from 'node:path';
import { RULES, SEVERITIES } from './rules.js';
import { detectInArg, detectSecret, entropy, findSecrets, isPlaceholder, looksLikeSetting, mask } from './secrets.js';
import { isCredentialParam, maskArgv, maskKnown, maskString, secretIndex } from './mask.js';
import { baseCommand, effectiveCommand, launchedPackages, parseDockerRun, argsAfterPackage, splitCommandLine } from './packages.js';
import { configSecretList } from './locate.js';
import { jsoncComments } from './jsonc.js';

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

// Template forms that README examples use: [YOUR_API_KEY], {API_KEY}, {{TOKEN}}, __TOKEN__.
const TEMPLATE_VALUE = /^(?:\[[^\]]*\]|\{[^{}]*\}|\{\{[^{}]*\}\}|__[A-Za-z0-9_]+__)$/;
// {{...}} anywhere in the value, found with indexOf so a long run of "{{" stays linear.
const hasMustache = (v) => { const a = v.indexOf('{{'); return a >= 0 && v.indexOf('}}', a + 2) >= 0; };
const isRealCredentialValue = (v) => !!v && v.length >= 8 && !isPlaceholder(v) && !TEMPLATE_VALUE.test(v.trim()) && !hasMustache(v);
// Parameter names that end in _key or _token without being credentials:
// pagination cursors, sort keys, idempotency keys.
const NOT_CRED_PREFIX = /^(?:sort|order|group|partition|page|next|prev|previous|continuation|cursor|sync|resume|pagination|idempotency|cache|lookup|primary|foreign|row|map|hash|search|filter|item|object|file|s3|bucket|public|pub)[_.-]?(?:key|token)$/i;
// A bare `auth` or a name that only ends in key/token is a weak hint: the value has to look like a random string too.
const STRONG_CRED_PARAM = /^(?:api[_-]?key|apikey|key|token|secret|password|passwd|pwd|sig|signature|credentials?|access[_-]?(?:token|key)|client[_-]?secret|(?:.*[_.-])?(?:api[_-]?key|apikey|access[_-]?token|secret|password|passwd|signature))$/i;
const looksRandom = (v) => v.length >= 16 && /\d/.test(v) && /[A-Za-z]/.test(v) && !/^[a-z]+(?:[_-][a-z]+)*\d{0,3}$/i.test(v);
function credentialQuery(k, v) {
  const key = String(k).replace(/([a-z0-9])([A-Z])/g, '$1_$2');
  if (!isCredentialParam(k) || NOT_CRED_PREFIX.test(key) || !isRealCredentialValue(v)) return false;
  return STRONG_CRED_PARAM.test(key) || looksRandom(v) || !!detectSecret(v, k);
}

/**
 * Masks every credential in a string meant for display (finding messages and
 * evidence). The masking is shared with every report: see src/mask.js.
 */
export const maskText = (text) => maskString(text);

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

// Registries whose names can be compared with each other. Several PyPI server
// names have been squatted on npm (npm replaced mcp-server-fetch and
// mcp-server-git with security holding packages), so npm and PyPI names are
// checked against both lists. Image names follow different rules.
const COMPARABLE = { npm: ['npm', 'pypi'], pypi: ['pypi', 'npm'], docker: ['docker'] };

// Real, published packages whose names sit next to a popular one. They are
// different projects with their own repository and release history, not
// typosquats. playwright-mcp is an independent Playwright server published
// since March 2025.
const KNOWN_DISTINCT = new Set(['mcp-server-gsc', 'mcp-server-ga4', 'mcp-server-gcp', 'mcp-server-kit', 'mcp-server-line', 'mcp-server-sqlite3',
  'playwright-mcp']);

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
 * The popular package a name imitates, and how: 'typo' for a misspelling, a
 * misspelled scope or an unscoped copy of a reference server
 * ("modelcontextprotocol-server-github"), 'scope' for a vendor package with
 * its scope dropped ("@stripe/mcp" as "stripe-mcp"), which unofficial ports also do.
 * @param {string} name package or image name
 * @param {string} [manager] 'npm', 'pypi' or 'docker'; when given, only registries whose names can collide are compared
 * 'shorthand' for the package name without its @ ("playwright/mcp"), which npx
 * reads as a GitHub owner/repo.
 * @returns {{popular: string, kind: 'typo'|'scope'|'shorthand'} | null}
 */
export function typosquatMatch(name, manager) {
  if (typeof name !== 'string' || !name) return null;
  const n = name.toLowerCase();
  if (POPULAR_PACKAGES.includes(n) || KNOWN_DISTINCT.has(n)) return null;
  const candidates = manager && COMPARABLE[manager] ? COMPARABLE[manager].flatMap((m) => POPULAR_BY_MANAGER[m]) : POPULAR_PACKAGES;
  // Same package name with the scope dropped, e.g. "modelcontextprotocol-server-github".
  // Checked first, because the dropped scope is also within the edit distance of a typo.
  for (const p of candidates) {
    if (!p.startsWith('@') || (n !== p.slice(1) && n !== p.slice(1).replace('/', '-'))) continue;
    // Nobody ports the reference servers under the protocol's own name, so that one stays a typosquat.
    // For npx, "owner/repo" without the @ is GitHub shorthand: code from github.com/owner/repo, not the package.
    if (n === p.slice(1) && manager !== 'docker') return { popular: p, kind: 'shorthand' };
    return { popular: p, kind: p.startsWith('@modelcontextprotocol/') ? 'typo' : 'scope' };
  }
  for (const p of candidates) {
    if (levenshtein(n, p) <= 2 && looksLikeTypo(n, p)) return { popular: p, kind: 'typo' };
    // A misspelled @modelcontextprotocol scope with the right package name.
    const bare = p.replace(/^@[^/]+\//, '');
    if (p.startsWith('@modelcontextprotocol/') && n.endsWith(`/${bare}`) && !n.startsWith('@modelcontextprotocol/')) {
      const scope = n.split('/')[0];
      if (levenshtein(scope, '@modelcontextprotocol') <= 3) return { popular: p, kind: 'typo' };
    }
  }
  return null;
}

/** The popular package `name` looks like a typosquat of, or null. */
export function typosquatOf(name, manager) {
  return typosquatMatch(name, manager)?.popular ?? null;
}

const SHELL_PACKAGES = /(desktop-commander|mcp-shell|shell-mcp|server-shell|shell-server|mcp-server-commands|terminal-mcp|mcp-terminal|server-terminal|cli-mcp-server|mcp-server-shell|iterm-mcp|win-cli-mcp|server-win-cli|claude-code-mcp|terminal[-_]controller|ssh-mcp|mcp-ssh)/i;
const FS_PACKAGES = /(server-filesystem|mcp\/filesystem|filesystem-mcp|mcp-filesystem|desktop-commander)/i;
// A local build of the reference filesystem server, e.g. .../src/filesystem/dist/index.js
const FS_SCRIPT = /\/(server-)?filesystem\//i;
// Bridges that connect a stdio client to a remote server given as an argument.
const BRIDGES = /(^|\/)(mcp-remote|supergateway|mcp-proxy)$/i;
// The same bridges as a folder in a script path (node_modules/mcp-remote/dist/proxy.js).
const BRIDGE_PATH = /(^|\/)(mcp-remote|supergateway|mcp-proxy)\//i;

// A config value that should be a string. JSON can hold anything, so arrays,
// numbers and objects are treated as absent rather than coerced.
const textOf = (v) => (typeof v === 'string' && v ? v : null);

function hostOf(url) {
  try { return new URL(url).host || maskText(url).slice(0, 80); } catch { return maskText(url).slice(0, 80); }
}

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
  node: {
    code: ['-r', '--require', '--import', '--loader', '--experimental-loader'],
    value: ['--env-file', '--env-file-if-exists', '--watch-path', '--title', '--inspect-port', '--debug-port', '--input-type', '--conditions', '-C',
      '--stack-size', '--max-old-space-size', '--max-semi-space-size', '--max-http-header-size', '--openssl-config', '--icu-data-dir',
      '--redirect-warnings', '--report-dir', '--report-directory', '--report-filename', '--report-signal', '--diagnostic-dir', '--cpu-prof-dir',
      '--cpu-prof-name', '--cpu-prof-interval', '--heap-prof-dir', '--heap-prof-name', '--heap-prof-interval', '--heapsnapshot-signal',
      '--heapsnapshot-near-heap-limit', '--disable-warning', '--localstorage-file', '--secure-heap', '--secure-heap-min', '--unhandled-rejections',
      '--trace-event-categories', '--trace-event-file-pattern', '--dns-result-order', '--experimental-default-type', '--experimental-config-file',
      '--network-family-autoselection-attempt-timeout', '--tls-cipher-list', '--tls-keylog', '--use-largepages', '--v8-pool-size',
      '--test-reporter', '--test-reporter-destination', '--test-name-pattern', '--test-skip-pattern', '--test-concurrency', '--test-shard',
      '--test-timeout', '--watch-kill-signal', '--policy-integrity', '--experimental-policy', '--snapshot-blob', '--tsconfig', '--project'],
    stop: ['-e', '--eval', '-p', '--print'],
  },
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

// Packages that are themselves interpreters: `npx tsx ./src/index.ts`.
const RUNNER_PACKAGES = new Set(['tsx', 'ts-node', 'node']);

// The scripts a server runs: through an interpreter command, or through an
// interpreter package started by npx and similar launchers.
function serverScripts(s) {
  const { base, args } = effectiveCommand(s);
  const pkgs = launchedPackages(s);
  if (!pkgs.length) return scriptArgs(base, args);
  const p = pkgs[0];
  if (p.kind !== 'registry' || !RUNNER_PACKAGES.has(String(p.name).toLowerCase())) return [];
  const at = args.indexOf(p.spec);
  return at < 0 ? [] : scriptArgs(String(p.name).toLowerCase(), args.slice(at + 1));
}

// Flags and their values in an argument list: --key=value, --key value, and
// HTTP header arguments such as "Authorization: Bearer <token>".
function secretsInArgs(list) {
  const hits = [];
  list.forEach((a, i) => {
    const det = detectInArg(a, i > 0 ? list[i - 1] : '');
    if (det) hits.push([i, det]);
  });
  return hits;
}

// Shells whose -c argument is a script, and the flags that introduce one
// (-c, -lc, -ec, -Command, cmd's /c).
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish', 'powershell', 'pwsh', 'cmd']);
const SCRIPT_FLAG = /^(?:-[a-z]{0,3}c|-command|\/c)$/i;

// The inline scripts in an argument list that starts with `command`: the
// argument after -c when the program is a shell. Each is split into words the
// way the shell would, so `API_TOKEN=x node server.js` and
// `export GITHUB_TOKEN=x && npx ...` are read like any other command line.
function shellScripts(command, list) {
  if (!SHELLS.has(baseCommand(command))) return [];
  const out = [];
  for (let i = 1; i < list.length; i++) {
    if (SCRIPT_FLAG.test(String(list[i - 1])) && /\s/.test(String(list[i]).trim())) out.push([i, splitCommandLine(String(list[i]))]);
  }
  return out;
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
  // Only text and numbers can hold a credential; nested objects and arrays are not values a client passes on.
  const scalar = (v) => (typeof v === 'string' || typeof v === 'number' ? String(v) : null);
  for (const [k, v] of Object.entries(s.env || {})) {
    const det = detectSecret(scalar(v), k);
    if (det) report(`env.${k}`, det, `${s.jsonPath}.env.${k}`);
  }
  for (const [k, v] of Object.entries(s.headers || {})) {
    const det = detectSecret(scalar(v), k);
    if (det) report(`headers.${k}`, det, `${s.jsonPath}.headers.${k}`);
  }
  // --api-key=xxx, --token xxx, --header "Authorization: Bearer xxx"
  const seen = new Set();
  for (const [i, det] of secretsInArgs(s.args)) { seen.add(det.match); report(`args[${i}]`, det, `${s.jsonPath}.args[${i}]`); }
  const once = (det, where, jsonPath) => {
    if (seen.has(det.match)) return;
    seen.add(det.match);
    report(where, det, jsonPath);
  };
  // sh -c 'API_TOKEN=x node server.js'
  const command = textOf(s.command);
  const args = Array.isArray(s.args) ? s.args.map(String) : [];
  for (const [i, words] of shellScripts(command, [command, ...args])) {
    for (const [, det] of secretsInArgs(words)) once(det, `args[${i - 1}]`, `${s.jsonPath}.args[${i - 1}]`);
  }
  // A command line written into `command`, also when more arguments follow in `args`.
  if (command && /\s/.test(command.trim())) {
    const words = splitCommandLine(command);
    for (const [, det] of secretsInArgs(words)) once(det, 'command', `${s.jsonPath}.command`);
    for (const [i, inner] of shellScripts(words[0], [...words, ...args])) {
      const where = i < words.length ? 'command' : `args[${i - words.length}]`;
      for (const [, det] of secretsInArgs(inner)) once(det, where, `${s.jsonPath}.${where}`);
    }
  }
  const url = textOf(s.url);
  if (url) {
    const det = detectSecret(url, '');
    if (det) report('url', det, `${s.jsonPath}.url`);
  }
  return out;
}

// The server URL, plus the remote URL given to a bridge such as mcp-remote.
function serverUrls(s) {
  const out = [];
  const url = textOf(s.url);
  if (url) {
    const key = ['url', 'serverUrl', 'httpUrl', 'endpoint'].find((k) => s.raw?.[k] === s.url) || 'url';
    out.push([url, `${s.jsonPath}.${key}`]);
  }
  const { base, args } = effectiveCommand(s);
  const pkgs = launchedPackages(s);
  // A bridge run from an install folder: node /opt/node_modules/mcp-remote/dist/proxy.js <url>
  const bridgeScript = !pkgs.length && scriptArgs(base, args).some((a) => BRIDGE_PATH.test(a.replace(/\\/g, '/')));
  if (BRIDGES.test(base) || bridgeScript || pkgs.some((p) => BRIDGES.test(p.name))) {
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
      if (credentialQuery(k, v)) {
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
      // ${IMAGE} or mcp/${NAME}: the variable may carry the tag, so nothing is known.
      if (!p.version && /\$|%[A-Za-z_][A-Za-z0-9_]*%/.test(p.spec)) continue;
      if (!p.pinned) out.push(finding('MCS004', ctx, p.version ? `Image ${spec} uses the mutable :latest tag.` : `Image ${spec} has no tag, so it resolves to :latest.`, { evidence: spec, jsonPath: argPath(s, p.spec) }));
    } else if (!p.pinned) {
      out.push(finding('MCS003', ctx,
        p.version ? `${name} is requested as "${maskText(p.version)}", which is not an exact version.` : `${name} runs whatever version is newest on ${p.manager} at launch.`,
        { evidence: spec, jsonPath: argPath(s, p.spec) }));
    }
    const squat = typosquatMatch(p.name, p.manager);
    if (squat?.kind === 'shorthand') out.push(finding('MCS013', ctx, `"${name}" has no @, so npx reads it as the GitHub repository ${name}, not the popular package "${squat.popular}".`, { evidence: name, jsonPath: argPath(s, p.spec) }));
    if (squat?.kind === 'typo') out.push(finding('MCS013', ctx, `"${name}" is very close to the popular package "${squat.popular}".`, { evidence: name, jsonPath: argPath(s, p.spec) }));
    // Unscoped community ports of scoped packages are common, so this one is a prompt to check the publisher.
    if (squat?.kind === 'scope') out.push(finding('MCS013', ctx, `"${name}" has the name of the popular package "${squat.popular}" without its scope. Check that it comes from the publisher you expect.`, { severity: 'medium', evidence: name, jsonPath: argPath(s, p.spec) }));
  }
  return out;
}

// The installed package folder of each agent, for `node .../claude-code/cli.js mcp serve`.
const AGENT_SCRIPT = { claude: /(^|\/)@anthropic-ai\/claude-code\//i, codex: /(^|\/)@openai\/codex\//i };

// Coding agents that can run as an MCP server and then expose their own
// shell and file tools: `claude mcp serve`, `codex mcp-server`.

function agentServer(base, args, pkgs) {
  let agent = ['claude', 'codex'].includes(base) ? base : null;
  let rest = args;
  const pkg = pkgs[0];
  if (!agent && pkg && /^@anthropic-ai\/claude-code$/i.test(pkg.name)) agent = 'claude';
  if (!agent && pkg && /^@openai\/codex$/i.test(pkg.name)) agent = 'codex';
  if (!agent && !pkg) {
    const script = scriptArgs(base, args).find((a) => !a.startsWith('-'));
    const where = script?.replace(/\\/g, '/');
    agent = where ? Object.keys(AGENT_SCRIPT).find((k) => AGENT_SCRIPT[k].test(where)) || null : null;
    if (agent) rest = args.slice(args.indexOf(script) + 1);
  }
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
  // Masked argument by argument, so a value after a --flag is hidden too. Only built when a finding uses it.
  const shown = () => maskArgv([s.command, ...s.args].filter(Boolean)).join(' ').slice(0, 160);
  const out = [];
  // MCS010: curl | sh
  if (/(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*(iex|invoke-expression)\b|(ba)?sh\s+<\(\s*curl/i.test(joined)) {
    out.push(finding('MCS010', ctx, 'The launch command pipes a downloaded script into a shell.', { evidence: shown() }));
  }
  const pkgs = launchedPackages(s);
  const shellPkg = pkgs.find((p) => SHELL_PACKAGES.test(p.name));
  const agent = agentServer(base, args, pkgs);
  // The server name is a label the user picked, so a match on it alone is a weaker signal.
  const label = String(s.name ?? '');
  const nameHint = !shellPkg && !agent && (SHELL_PACKAGES.exec(label) || (pkgs.length === 0 && /\b(shell|terminal)\b/i.exec(label)));
  if (shellPkg) {
    out.push(finding('MCS007', ctx, `"${maskText(shellPkg.name)}" exposes shell / command execution tools.`, { evidence: maskText(shellPkg.spec), jsonPath: argPath(s, shellPkg.spec) }));
  } else if (agent) {
    out.push(finding('MCS007', ctx, agent, { evidence: shown(), jsonPath: s.command ? `${s.jsonPath}.command` : s.jsonPath }));
  } else if (nameHint) {
    const urls = s.command ? [] : serverUrls(s);
    const where = urls.length ? `remote server at ${hostOf(urls[0][0])}` : 'server';
    out.push(finding('MCS007', ctx,
      `The ${where} is named "${maskText(label)}", and "${nameHint[0]}" in the name suggests shell or command execution tools. Only the name matched; check which tools it offers.`,
      { severity: 'medium', evidence: maskText(label), jsonPath: s.jsonPath }));
  } else if (['bash', 'sh', 'zsh', 'powershell', 'pwsh'].includes(base) && args.some((a) => /^(-c|-command|-Command)$/i.test(a))) {
    // Inline shell script as the launcher is worth a look, but it is not a shell tool by itself.
    out.push(finding('MCS007', ctx, 'Server is launched through an inline shell script, which hides what actually runs.', { severity: 'low', evidence: shown() }));
  }
  return out;
}

function checkFilesystem(ctx) {
  const s = ctx.server;
  const out = [];
  const pkgs = launchedPackages(s);
  const { base, args } = effectiveCommand(s);
  // For a server run from a local build (node .../filesystem/dist/index.js or
  // npx tsx .../filesystem/index.ts), the script itself is not an allowed directory.
  const scripts = serverScripts(s);
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
  const { cmd } = effectiveCommand(s);
  const candidates = [
    [cmd, s.command === cmd ? `${s.jsonPath}.command` : null],
    [textOf(s.cwd), `${s.jsonPath}.cwd`],
    ...serverScripts(s).map((a) => [a, null]),
    ...launchedPackages(s).filter((p) => p.kind === 'local').map((p) => [p.spec, null]),
  ].filter(([c]) => c);
  const hit = candidates.find(([c]) => TEMP_DIR.test(String(c).replace(/\\/g, '/')));
  if (!hit) return [];
  const [value, jsonPath] = hit;
  return [finding('MCS014', ctx, `Runs code from ${maskText(value)}.`, { evidence: maskText(value), jsonPath: jsonPath || argPath(s, value) })];
}

export const SERVER_CHECKS = [checkSecrets, checkUrl, checkPackages, checkShell, checkFilesystem, checkDocker, checkAutoApprove, checkLocation];

// ---------------- File-level checks ----------------

// Characters that only serve to hide or reorder text: bidirectional
// embeddings, overrides and isolates, invisible math operators, a byte order
// mark inside the text, and tag characters outside a flag emoji.
const isHidingCode = (c) => (c >= 0x202A && c <= 0x202E) || (c >= 0x2061 && c <= 0x2064) || (c >= 0x2066 && c <= 0x2069) || c === 0xFEFF || (c >= 0xE0000 && c <= 0xE007F);
// Every code point INVISIBLE matches.
const isInvisibleCode = (c) => c === 0xAD || c === 0x180E || (c >= 0x200B && c <= 0x200F) || (c >= 0x202A && c <= 0x202E) || (c >= 0x2060 && c <= 0x2064)
  || (c >= 0x2066 && c <= 0x2069) || c === 0xFEFF || (c >= 0xE0000 && c <= 0xE007F);
const isAsciiVisible = (c) => c >= 0x21 && c <= 0x7E;
// Joiners that build emoji (a family, a profession with a skin tone) and the tag sequence of a subdivision flag.
// A subdivision flag spells a short code in lowercase tag letters and digits:
// a two-letter region and one to three more (gbeng, gbsct, usca). Longer runs,
// spaces and capitals are text hidden behind a flag, not a flag.
const FLAG_TAGS = String.raw`\u{1F3F4}[\u{E0061}-\u{E007A}]{2}[\u{E0030}-\u{E0039}\u{E0061}-\u{E007A}]{1,3}\u{E007F}`;
const FILE_EMOJI_JOINS = new RegExp(String.raw`(?<=[\p{Extended_Pictographic}\p{Emoji_Modifier}]\uFE0F?)\u200D(?=\p{Extended_Pictographic})|${FLAG_TAGS}`, 'gu');

/**
 * The invisible characters in config text that can hide something, as
 * { index, code } in the text without a leading byte order mark. Zero-width
 * characters, soft hyphens and direction marks are part of ordinary writing
 * in Persian, Arabic, Hebrew and Indic scripts and in emoji, so they count
 * only inside a token of visible ASCII (a key, command, argument or URL) or
 * as a run of two or more. Bidirectional controls and tag characters always count.
 * @returns {{index: number, code: number}[]}
 */
export function hiddenCharacters(text) {
  const body = String(text ?? '').replace(/^\uFEFF/, '');
  const clean = body.replace(FILE_EMOJI_JOINS, (m) => ' '.repeat(m.length));
  // The code point that ends just before i (-1 at the start).
  const before = (i) => {
    if (i <= 0) return -1;
    const c = clean.charCodeAt(i - 1);
    return c >= 0xDC00 && c <= 0xDFFF && i >= 2 ? clean.codePointAt(i - 2) : c;
  };
  const out = [];
  const re = new RegExp(INVISIBLE.source, 'gu');
  for (let m = re.exec(clean); m; m = re.exec(clean)) {
    const code = m[0].codePointAt(0);
    const end = m.index + m[0].length;
    const prev = before(m.index);
    const next = end < clean.length ? clean.codePointAt(end) : -1;
    const run = isInvisibleCode(prev) || isInvisibleCode(next);
    const inToken = isAsciiVisible(prev) && isAsciiVisible(next);
    if (isHidingCode(code) || run || inToken) out.push({ index: m.index, code });
  }
  return out;
}

function checkFileUnicode(ctx) {
  const t = typeof ctx.config.text === 'string' ? ctx.config.text : '';
  const body = t.charCodeAt(0) === 0xfeff ? t.slice(1) : t;
  const hits = hiddenCharacters(body);
  if (!hits.length) return [];
  const line = body.slice(0, hits[0].index).split('\n').length;
  const codes = [...new Set(hits.map((h) => `U+${h.code.toString(16).toUpperCase().padStart(4, '0')}`))];
  const f = finding('MCS015', ctx, `${hits.length} invisible character(s) found, first on line ${line}.`, { evidence: codes.join(', ') });
  f.line = line; // there is no JSON path to look the line up from
  return [f];
}

// "key": "value" pairs in a commented-out piece of JSON. Bounded, so it runs in linear time.
const COMMENT_PAIR = /"([\w.-]{1,128})"[ \t]{0,8}:[ \t]{0,8}"([^"\\\n]{1,1024})"/g;
// Quotes and punctuation around a word of a comment, trimmed by hand (a
// pattern anchored at the end would be quadratic on a long run of them).
const EDGE = new Set(['"', "'", '`', ',', ';', '{', '}', '[', ']', '(', ')']);
function trimEdges(w) {
  let a = 0;
  let b = w.length;
  while (a < b && EDGE.has(w[a])) a++;
  while (b > a && EDGE.has(w[b - 1])) b--;
  return w.slice(a, b);
}

// MCS001 for credentials in comments. A JSONC config is committed with its
// comments, so a commented-out server or an old key is as exposed as a value.
function checkCommentSecrets(ctx) {
  const { config } = ctx;
  const text = typeof config.text === 'string' ? config.text : '';
  if (!text.includes('/')) return [];
  const project = config.source?.scope === 'project';
  const out = [];
  const seen = new Set();
  for (const c of jsoncComments(text)) {
    // No credential MCS001 reports is shorter than this.
    if (c.text.trim().length < 8) continue;
    const dets = [...findSecrets(c.text)];
    // Words of the comment, read like command line arguments: API_KEY=..., --token ...
    const words = c.text.split(/\s+/).map(trimEdges).filter(Boolean);
    for (const [, d] of secretsInArgs(words)) dets.push(d);
    for (const m of c.text.matchAll(COMMENT_PAIR)) dets.push(...findSecrets(m[2], m[1]));
    for (const det of dets) {
      if (seen.has(det.secret)) continue;
      seen.add(det.secret);
      const at = c.text.indexOf(det.secret);
      const line = c.line + (at > 0 ? c.text.slice(0, at).split('\n').length - 1 : 0);
      let severity = det.confidence === 'high' ? 'high' : 'medium';
      if (project) severity = 'critical';
      const f = finding('MCS001', ctx,
        `${det.type} found in a comment on line ${line}${project ? '. This is a project file that is likely committed to git' : ''}.`,
        { severity, evidence: mask(det.match) });
      f.line = line;
      out.push(f);
    }
  }
  return out;
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

// Each entry is [pattern, reason, kind]. The kind decides how much a reason
// weighs on its own and together with others (see poisonSeverity):
//   override - tells the model to drop its instructions (critical alone)
//   inject   - framing that talks to the model as its operator (tags, fake headers)
//   conceal  - asks the model to keep something from the user
//   exfil    - moves data into a parameter, a fixed recipient or an upload
//   dest     - names an external address or uploads a file (weak alone)
//   precall  - asks for a file-reading side task before the tool runs
//   exec     - pipes a download into a shell (weak alone; install lines do this)
//   obfusc   - asks the model to decode and follow hidden text
//   target   - names a credential or config file (weak alone)
// The reports reuse these patterns to highlight the evidence.
// Anchored at the start of its run and bounded, so a long run of word characters is not
// rescanned from every position inside it.
const EMAIL = String.raw`(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){0,8}\.[a-z]{2,24}\b`;
const PHONE = String.raw`\+\d[\d ()-]{6,}\d`;
// What safety guidance keeps from the user ("Do not reveal secret values to users").
// Hiding a secret protects the user; hiding an action from them is the attack.
const GUARDED = String.raw`(?:secrets?|(?:api[\s_-]?)?keys?|tokens?|passwords?|passphrases?|credentials?|values?|pins?)`;
// Only when the guarded word is the thing withheld: not the subject of a clause ("the token
// was sent") and not an adjective ("secret instructions", "key steps").
const GUARDED_NOT_OBJECT = String.raw`\s+(?:was|were|is|are|has|have|had|been|being|got|gets|will|would|did|does|went|instructions?|steps?|actions?|prompts?|tasks?|operations?|commands?|calls?|behaviou?r|purpose|plans?)\b`;
const GUARDED_OBJECT = String.raw`(?!\s+(?:the\s+|any\s+|their\s+|your\s+|its\s+|his\s+|her\s+|raw\s+)?(?:[\w-]+\s+){0,2}${GUARDED}\b(?!${GUARDED_NOT_OBJECT}))`;
// Every pattern here must stay linear in its input: gaps are bounded and stop at sentence
// ends, a tag's attributes stop at the next "<", and a comment body stops at "-->" or "<!--".
export const POISON = [
  // The attribute run cannot cross a "<", so each scan ends before the next tag starts.
  [/<\s*(important|system|instructions?|secret|hidden|admin)\b(?=[^<>]*>)/i, 'hidden tag', 'inject'],
  [/^[ \t]*(?:\[\s*(?:system|admin)\s*\]|#{1,6}[ \t]*system[ \t]+(?:instructions?|message|override|prompt|note)\b)/im, 'fake system header', 'inject'],
  [/\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|other|system|original)\s+(?:instructions|prompts?|rules|guidelines)\b(?!\s+(?:in|inside|within|contained|embedded|found)\b)|\b(?:ignore|disregard|forget)\s+(?:your\s+(?:own\s+)?(?:instructions|prompts?|rules|guidelines)\b|all\s+(?:of\s+)?(?:the\s+|your\s+)?(?:instructions|prompts?)\b(?!\s+(?:in|inside|within|contained|embedded|found|on)\b))|\b(?:ignore|disregard)\b[^.\n]{0,30}\b(?:system\s+prompt|safety\s+(?:guidelines|rules|policies))\b|\btakes?\s+priority\s+over\s+(?:the\s+)?(?:user|system)\b/i, 'instruction override', 'override'],
  [new RegExp(String.raw`\b(?:do\s+not|don['’]?t|never|must\s+not|should\s+not|shouldn['’]?t)\s+(?:(?:tell|inform|reveal|disclose|let|say|explain|report)\b${GUARDED_OBJECT}[^.;\n]{0,40}\b(?:user|users|them|anyone|human)\b(?!['’]s)${GUARDED_OBJECT}|(?:notify|alert|mention)\b(?:\s+(?:the\s+)?(?:user|users|them|anyone)\s+(?:about|of|that)\s+(?:this|it|these|that|what|the\s+(?:call|upload|request|step|action|instruction))\b|${GUARDED_OBJECT}[^.;\n]{0,40}\bto\s+(?:the\s+)?(?:user|users|them|anyone|human)\b))|\bwithout\s+(?:telling|informing|notifying|alerting|letting)\s+(?:the\s+)?(?:user|them|anyone)\b|\bkeep\s+(?:this|it|that|these)\s+(?:(?:step|instruction|part|information)\s+)?(?:to\s+yourself|quiet|hidden|from\s+the\s+user)\b|\bkeep\s+quiet\b|\buser\s+(?:does\s+not|doesn['’]?t|need\s+not|needn['’]?t)\s+(?:need\s+to\s+)?(?:know|be\s+told|be\s+informed)\b|\b(?:user|users)\s+(?:must|should|will|may|can)\s+(?:never|not)\s+(?:find\s+out|know|learn|notice|discover|suspect)\s+(?:that|about|of|what|this|it)\b|\b(?:hide|conceal)\s+(?:this|it|these|that)\b[^.\n]{0,30}\bfrom\s+(?:the\s+)?user\b`, 'i'), 'asks the model to hide something from the user', 'conceal'],
  [/\b(?:before|prior\s+to)\s+(?:using|calling|invoking|running)\s+(?:this|any|the)\s+(?:tool|function)\b[^.\n]{0,80}\b(?:read|cat|open|fetch|send|pass|include|copy|upload)\b[^.\n]{0,40}?(?:~[/\\]|\$HOME|%USERPROFILE%|\/\w|\\\w|\.\w+\/|\b(?:(?:ssh|private|api)\s+keys?|credentials?|tokens?|secrets?|passwords?)\b)/i, 'pre-call side task', 'precall'],
  [/(?<![\w.$-])\.(?:ssh|aws|gnupg|kube|docker|netrc|git-credentials|npmrc|pypirc|pgpass|bash_history|zsh_history|bashrc|zshrc)\b(?![\w-]|\.[A-Za-z])|(?<![\w.$-])\.env\b(?!-|\.(?:example|sample|template|tmpl|dist|defaults?)\b)|\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|\bcredentials\.json\b|\bclaude_desktop_config\b|(?<![\w-])mcp\.json\b|\/etc\/(?:passwd|shadow)\b|(?<![\w-])[\w-]{1,100}\.keychain(?:-db)?\b/i, 'references sensitive files', 'target'],
  [/\b(?:pass|include|put|add|copy|paste|append|insert|place|embed|attach|send)\b(?:[^.\n]|\.(?=\S)){0,100}?\b(?:as|in|into|inside|within|to)\s+(?:the\s+|a\s+)?['"`]?(?:sidenote|side_note|side-note)\b|\b(?:pass|include|put|copy|paste|append|insert|place|embed)\s+(?:its|their|the|this|that|all)\s+(?:full\s+|entire\s+|whole\s+)?(?:contents?|output|text)\b(?:[^.\n]|\.(?=\S)){0,40}?\b(?:as|in|into|inside)\s+(?:the\s+|a\s+)?(?:['"`]?(?<param>[\w-]{1,30})['"`]?\s+)?(?:parameters?|params?|arguments?|args?|field)\b/i, 'smuggles data through a parameter', 'exfil'],
  [new RegExp(String.raw`\b(?:change|set|replace|redirect|switch|override|route)\s+(?:the\s+|all\s+|every\s+)?(?:recipient|destination|receiver|to\s+address|phone\s+number|email\s+address|messages?)s?\b[^.]{0,30}?\bto\s+['"\x60]?(?:${PHONE}|${EMAIL}|https?:\/\/)|\b(?:always\s+)?(?:bcc|cc)\s+(?:every|all|each)\b[^.\n]{0,40}?(?:${PHONE}|${EMAIL})`, 'i'), 'redirects messages to a fixed recipient', 'exfil'],
  [/\b(?:curl|wget)\b[^\n|;]{0,80}?\s(?:(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form)[\s=]+['"]?(?:[\w-]+=)?@|(?:-T|--upload-file|--post-file|--body-file)[\s=]+['"]?(?:~|\$|%|\.{0,2}[/\\]|[A-Za-z]:\\|[\w-]*\.\w))/i, 'uploads a local file', 'dest'],
  // The lookahead skips verbs with no address in reach; the address must start a token.
  [new RegExp(String.raw`\b(?:send|post|upload|forward|exfiltrate|transmit|copy)\b(?=[^\n]{0,110}?(?:\/\/|@|\+\d))(?:[^.\n]|\.(?=\S)){0,60}\b(?:to|via)\b(?:[^.\n]|\.(?=\S)){0,40}?(?<=[\s"'(<:=\x60\[])(?:https?:\/\/[^\s"'<>)]+|${EMAIL}|${PHONE})`, 'i'), 'sends data to an external destination', 'dest'],
  [/\b(?:curl|wget)\b[^\n|]{0,100}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i, 'pipes a download into a shell', 'exec'],
  [/\b(?:decode|base64[- ]decode|atob|unescape|rot13)\b[^.\n]{0,40}\b(?:follow|execute|run|obey|carry\s+out)\b/i, 'asks the model to decode and follow hidden text', 'obfusc'],
];

// Instructions in an HTML comment. Scanned in code rather than with a pattern so that a
// nested "<!--" cannot end the comment early and each character is read once: a comment
// runs from "<!--" to the first "-->", as in HTML, and an unclosed one is not a comment.
export const COMMENT_LABEL = 'instructions in an HTML comment';
const COMMENT_WORD = /\b(?:assistant|model|ai|llm|claude|agent|you\s+must|you\s+should)\b/i;
function findComments(text) {
  const out = [];
  for (let pos = 0; ;) {
    const i = text.indexOf('<!--', pos);
    if (i < 0) break;
    const j = text.indexOf('-->', i + 4);
    if (j < 0) break;
    const m = COMMENT_WORD.exec(text.slice(i + 4, j));
    if (m) out.push({ start: i, end: i + 4 + m.index + m[0].length });
    pos = j + 3;
  }
  return out;
}

// Not a reason by itself: makes a parameter-smuggling or sending instruction critical.
const SECRET_DATA = /\b(?:ssh|private|gpg|pgp)\s+keys?\b|\bapi[\s_-]?keys?\b|\bpasswords?\b|\baccess\s+tokens?\b|\benvironment\s+variables?\b|\benv\s+vars?\b|\b(?:conversation|chat|message)\s+(?:history|so\s+far|log)\b|\b(?:full|entire|whole)\s+conversation\b|\b(?:previous|last|recent)\s+messages\b|\bseed\s+phrase\b/i;

// Data theft through a parameter or to an outside address, whatever the parameter is called:
// "read <secret> and put it in the X parameter", "copy <secret> into X", "send <secret> to
// https://...", "set the X parameter to the contents of <secret>". It needs a sensitive
// source handed to a place it does not belong. Using a credential for the tool's own job
// is not theft: "read the bot token from SLACK_TOKEN and put it in the token parameter",
// "pass the private key as the key parameter to sign the JWT", "load credentials and use
// them to sign requests to https://s3.amazonaws.com".
const SENSITIVE_FILE = POISON.find(([, , kind]) => kind === 'target')[0].source;
// Sources the model has to go and get; naming them next to a hand-off is enough.
const SOURCE_OTHER = String.raw`\b(?:environment|env)\s+var(?:iable)?s?\b|\b(?:conversation|chat|message)\s+(?:history|so\s+far|log|transcript)\b|\b(?:full|entire|whole|complete)\s+(?:conversation|chat|transcript)\b|\b(?:previous|prior|earlier|last|recent)\s+messages\b|\b(?:ssh|private|gpg|pgp)\s+keys?\b|\bseed\s+phrase\b|\b(?:mnemonic|recovery)\s+phrase\b|\b(?:system\s+prompt|your\s+instructions)\b|\b(?:all|every)\s+(?:of\s+(?:the|your)\s+)?(?:api[\s_-]?keys?|tokens?|passwords?|secrets?|credentials?)\b`;
// Secrets a tool may legitimately ask for as input; they only count when the text asks the
// model to read or collect them first.
const SOURCE_WEAK = String.raw`\bapi[\s_-]?keys?\b|\bpasswords?\b|\b(?:access|auth|bearer|session|refresh)\s+tokens?\b|\bsecrets?\b|\bcredentials?\b|\bcookies?\b`;
const PARAM = String.raw`(?:parameters?|params?|arguments?|args?|fields?|property)`;
const NAME = String.raw`['"\x60]?([\w.-]{1,40})['"\x60]?`;
export const STEAL = {
  // Group 1: a sensitive file; group 2: another sensitive source; neither: a plain secret.
  source: new RegExp(`(${SENSITIVE_FILE})|(${SOURCE_OTHER})|${SOURCE_WEAK}`, 'gi'),
  // Content verbs move the data itself; "pass ~/.ssh/id_rsa as keyPath" only moves a path.
  move: /\b(?:(copy|paste|dump|leak|exfiltrate|smuggle|stuff|embed|upload|transmit)|include|insert|append|put|place|pass|send|forward|post|add|attach|submit|supply|e-?mail|mail)\b/gi,
  gather: /\b(?:read|open|cat|collect|gather|grab|extract|dump|copy|harvest|scrape|steal|get|fetch|obtain|retrieve|load|take|look\s+up|find|access)\b/gi,
  // Group 1: the verb; group 2: a word that refers back ("it", "its contents").
  handoff: /\b(put|pass|include|add|copy|paste|append|insert|place|embed|attach|send|stuff|write|store|save|forward|post|upload|submit|provide|supply|set|use|enter|fill|e-?mail|mail|transmit)\s+(?:(it|them|its\s+(?:full\s+|entire\s+|raw\s+)?(?:contents?|values?|text|data|lines|output|body)|their\s+(?:full\s+|entire\s+|raw\s+)?(?:contents?|values?|text|data|lines|output)|this|that|these|those|everything|all\s+of\s+(?:it|them)|what\s+you\s+(?:find|found|read|get|got|see))|the\s+(?:full\s+|entire\s+|whole\s+)?(?:contents?|file|keys?|values?|data|text|result|output))\b/gi,
  // Group 1 or 3: the parameter's name; 2: a side note; 4: an outside address.
  sink: new RegExp(String.raw`\b(?:as|in|into|inside|within|to|through|via|under|using)\s+(?:the\s+|a\s+|an\s+|your\s+|its\s+|this\s+tool['’]?s\s+)?(?:(?:value|contents?)\s+of\s+(?:the\s+|a\s+)?)?(?:(?:${NAME}\s+)?${PARAM}\b|['"\x60]?(sidenote|side_note|side-note)\b)|\b(?:in|with)\s+(?:your|the|this)\s+(?:tool\s+)?(?:call|request)\s+(?:as|in)\s+(?:the\s+)?${NAME}|(https?:\/\/[^\s"'<>)]+|${EMAIL}|${PHONE})`, 'gi'),
  // "Set the notes parameter to the contents of ...", "the notes field must contain ...".
  // Group 1 or 2: the parameter's name; 3: "the contents of".
  setsink: new RegExp(String.raw`(?:\b(?:set|fill|populate)\s+(?:the\s+|a\s+)?${NAME}\s+${PARAM}\s+(?:to|with)|(?<![\w.-])${NAME}\s+${PARAM}\s+(?:must|should|shall|will)\s+(?:always\s+)?(?:contain|include|hold|be\s+set\s+to|be\s+filled\s+with|be))\s+(?:(?:the\s+)?(?:full\s+|entire\s+|whole\s+|raw\s+)?(contents?|text|output|data|values?|body)\s+of\s+)?(?:the\s+(?:file\s+)?)?['"\x60]?(?:cat\s+)?`, 'gi'),
  boundary: /(?:[.!?](?=\s)|\n)\s*/g,
};
// Parameter names where a credential belongs. Split on case and punctuation, so keyPath,
// api_key and X-Auth-Token all count.
const CREDENTIAL_NAME = new Set(['token', 'tokens', 'key', 'keys', 'apikey', 'secret', 'secrets', 'password', 'passwords', 'passwd', 'pwd', 'passphrase',
  'pass', 'auth', 'authorization', 'authentication', 'credential', 'credentials', 'cred', 'creds', 'bearer', 'env', 'environment', 'cert', 'certificate',
  'signature', 'sig', 'signing', 'header', 'headers', 'session', 'cookie', 'cookies', 'jwt', 'pem', 'login', 'otp', 'pin', 'keychain', 'keyring', 'vault']);
const credentialName = (name) => !!name && name.replace(/([a-z\d])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z\d]+/).some((w) => CREDENTIAL_NAME.has(w));
// "the private key file path", "the environment variable names": a reference, not the secret.
const NOT_CONTENT = /^\s+(?:file\s+)?(?:paths?|locations?|filenames?|file\s+names?|names?|ids?|fingerprints?|alias(?:es)?|lengths?|formats?|types?)\b/i;
// "Credentials are read from environment variables" describes the tool; it asks for nothing.
const PASSIVE = /\b(?:is|are|was|were|be|been|being)\s+(?:\w+ly\s+)?$/i;
// "Use them to sign requests to https://..." is authentication, not sending them anywhere.
const NOT_TO_ADDRESS = new Set(['use', 'set', 'enter', 'fill']);
const PURPOSE = /\b(?:to|in\s+order\s+to)\s+(?:sign|authenticate|authorize|log\s*in|connect)\b|\b(?:in|as|via|using)\s+(?:the\s+|an?\s+)?(?:[\w-]+\s+)?(?:header|bearer\s+token)\b/i;
const SWEEPING = /^(?:full|entire|whole|complete|all|every)\b|so\s+far$|phrase$/i;

function allMatches(re, text) {
  const out = [];
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text))) {
    if (!m[0]) { re.lastIndex++; continue; }
    out.push({ start: m.index, end: m.index + m[0].length, m });
  }
  return out;
}

// Index of the last item of a list sorted by position that ends at or before p, and of the
// first that starts at or after p.
const lastEndingBy = (list, p) => { let lo = 0; let hi = list.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (list[mid].end <= p) lo = mid + 1; else hi = mid; } return lo - 1; };
const firstStartingAt = (list, p) => { let lo = 0; let hi = list.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (list[mid].start < p) lo = mid + 1; else hi = mid; } return lo; };

/**
 * Find "collect a secret, then hand it to a parameter or an address" (at most `limit` spans).
 * Every pattern runs once over the text with no cap on its matches, and each source looks
 * at a bounded number of neighbours, so the cost is linear in the text.
 */
function findTheft(text, limit = 1) {
  const found = [];
  const bounds = allMatches(STEAL.boundary, text).map((b) => b.start);
  // Number of sentence ends before position p.
  const sentence = (p) => { let lo = 0; let hi = bounds.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (bounds[mid] < p) lo = mid + 1; else hi = mid; } return lo; };
  const sources = allMatches(STEAL.source, text)
    .map((x) => ({ ...x, file: !!x.m[1], strong: !!(x.m[1] || x.m[2]), sweeping: SWEEPING.test(x.m[0]) }))
    .filter((x) => !NOT_CONTENT.test(text.slice(x.end, x.end + 40)));
  if (!sources.length) return found;
  const moves = allMatches(STEAL.move, text).map((x) => ({ ...x, content: !!x.m[1] }));
  const gathers = allMatches(STEAL.gather, text).filter((g) => !PASSIVE.test(text.slice(Math.max(0, g.start - 30), g.start)));
  const handoffs = allMatches(STEAL.handoff, text).map((x) => ({ ...x, verb: x.m[1].toLowerCase(), back: !!x.m[2] }));
  const sinks = allMatches(STEAL.sink, text).map((x) => ({ ...x, dest: !!x.m[4], generic: !!x.m[3], name: x.m[1] || x.m[3] || null }));
  const setsinks = allMatches(STEAL.setsink, text).map((x) => ({ ...x, name: x.m[1] || x.m[2], contents: !!x.m[3] }));
  // A parameter named for the secret (token, apiKey, password) is where it belongs.
  const belongs = (k, s, sweep) => !k.dest && !sweep && credentialName(k.name);
  // A plain secret named next to "in the request as X" is how most APIs authenticate.
  const fitsSource = (k, s) => !(k.generic && !s.strong);
  const sinkAfter = (p, within, ok) => {
    for (let i = firstStartingAt(sinks, p); i < sinks.length && sinks[i].start - p <= within; i++) if (ok(sinks[i])) return sinks[i];
    return null;
  };
  const overlaps = (start, end) => found.some((f) => start < f.end && end > f.start);
  const add = (start, end, dest) => {
    if (overlaps(start, end)) return false;
    found.push({ start, end, dest });
    return found.length >= limit;
  };
  for (const s of sources) {
    if (overlaps(s.start, s.end)) continue;
    const ss = sentence(s.start);
    // "read <source> ... put it in <sink>": gather verb, source, a hand-off naming it, the sink.
    // Only the nearest gather verb matters: it is the closest one in the sentence, and the
    // only one that can have a plain secret as its object.
    let hit = null;
    const g = gathers[lastEndingBy(gathers, s.start)];
    // A plain secret must be the object of the verb ("fetch the user's password"), not a
    // word further on ("read the docs to find your API key").
    const gathered = g && s.start - g.end <= 160 && sentence(g.start) === ss
      && (s.strong || /^\s+(?:[\w'’-]+\s+){0,3}$/.test(text.slice(g.end, s.start)));
    // Every hand-off within reach is tried; the distance limits bound the work, not a count.
    for (let hi = gathered ? firstStartingAt(handoffs, s.end) : handoffs.length; hi < handoffs.length && handoffs[hi].start - s.end <= 200; hi++) {
      const h = handoffs[hi];
      const hs = sentence(h.start);
      // A later sentence has to refer back to the secret: "Read X. Then put it in ...".
      if (hs !== ss && (!h.back || hs - ss > 1)) continue;
      const sink = sinkAfter(h.end, 60, (k2) => sentence(k2.start) === hs && fitsSource(k2, s)
        && (k2.dest ? !NOT_TO_ADDRESS.has(h.verb) && !PURPOSE.test(text.slice(h.end, k2.start)) : !belongs(k2, s, s.sweeping)));
      if (sink) { hit = { start: g.start, end: sink.end, dest: sink.dest }; break; }
    }
    if (hit) { if (add(hit.start, hit.end, hit.dest)) return found; continue; }
    // "copy <source> into <sink>" in one clause. A file's path is not its contents, so moving a
    // file needs a content verb or "the contents of"; a plain secret needs an outside address.
    const mv = moves[lastEndingBy(moves, s.start)];
    if (!mv || s.start - mv.end > 100 || sentence(mv.start) !== ss) continue;
    const between = text.slice(mv.end, s.start);
    const contents = mv.content || /\b(?:contents?|text|output|data|values?)\s+of\b/i.test(between);
    // "Pass the conversation history in the messages parameter" is how a chat tool works;
    // "the full conversation so far" or "every API key" is not.
    const sweep = s.sweeping || /\byour\s+$/i.test(between);
    const toParam = s.file ? contents : s.strong && (mv.content || sweep);
    const sink = sinkAfter(s.end, 120, (k) => sentence(k.start) === ss && fitsSource(k, s)
      && (k.dest ? (contents || !s.file) && !PURPOSE.test(text.slice(s.end, k.start)) : toParam && !belongs(k, s, sweep)));
    if (sink && add(mv.start, sink.end, sink.dest)) return found;
  }
  // "Set the notes parameter to the contents of <source>": the sink comes first.
  for (const k of setsinks) {
    const s = sources[firstStartingAt(sources, k.end)];
    if (!s || s.start - k.end > 30 || /\s/.test(text.slice(k.end, s.start)) || !s.strong || belongs(k, s, s.sweeping)) continue;
    if (!(k.contents || (!s.file && s.sweeping))) continue;
    if (add(k.start, s.end, false)) return found;
  }
  return found.sort((a, b) => a.start - b.start);
}

// Greek and Cyrillic letters that look like Latin ones, mapped before matching.
const CONFUSABLE = Object.fromEntries([...
  'ΑAΒBΕEΖZΗHΙIΚKΜMΝNΟOΡPΤTΥYΧXοoνvАAВBЕEКKМMНHОOРPСCТTХXУYІIЈJЅSаaеeоoрpсcуyхxіiјjѕsһhԁdԛqԝw',
].reduce((pairs, ch, i, a) => (i % 2 ? pairs : [...pairs, [ch, a[i + 1]]]), []));
const INVISIBLE_ONE = new RegExp(`^(?:${INVISIBLE.source})$`, 'u');
// Zero-width joiners inside emoji and the tag characters of subdivision flags are legitimate.
const EMOJI_JOINS = new RegExp(String.raw`(?<=\p{Extended_Pictographic}\uFE0F?)\u200D(?=\p{Extended_Pictographic})|${FLAG_TAGS}`, 'gu');
const TAG_TEXT = /[\u{E0020}-\u{E007E}]{4,}/gu;
const BASE64_RUN = /[A-Za-z0-9+/]{40,}={0,2}/g;

const MAX_TEXT = 200_000;
const MAX_NODES = 20_000;
const MAX_DEPTH = 64;

// Keys whose children are named schemas, so a property called "default" is still a schema.
const SCHEMA_MAPS = new Set(['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas']);
// Keys holding values or structure rather than prose. Their strings are scanned, but a
// file path in a default or an enum (an SSH tool's key path) is not a finding on its own.
const VALUE_KEYS = new Set(['default', 'examples', 'example', 'enum', 'const', 'pattern', 'format', 'type', 'required',
  '$ref', '$id', '$schema', '$anchor', '$dynamicRef', '$dynamicAnchor', 'contentEncoding', 'contentMediaType']);

/**
 * Collect every string in a tool definition that the model may see: the description,
 * title, annotations, and every string anywhere in inputSchema and outputSchema.
 * When a size, node or depth limit stops the walk, the result has `truncated` set so the
 * caller can say the tool was not fully checked instead of reporting it as clean.
 * @returns {{text: string, kind: 'prose'|'value'}[] & {truncated?: boolean}}
 */
function toolTexts(t) {
  const out = [];
  let nodes = 0;
  let size = 0;
  const seen = new Set();
  const add = (s, kind) => {
    if (typeof s !== 'string') return;
    if (size >= MAX_TEXT) { out.truncated = true; return; }
    let text = s.replace(/[ \t]+/g, ' ').trim();
    if (!text) return;
    // Short tokens such as "string" or "#/$defs/X" carry no instructions and only clutter the evidence.
    if (kind === 'value' && text.length < 40 && !/\s/.test(text)) return;
    if (size + text.length > MAX_TEXT) { text = text.slice(0, MAX_TEXT - size); out.truncated = true; }
    size += text.length;
    out.push({ text, kind });
  };
  // The node and text budgets end the whole walk; the depth limit only skips that branch.
  const spent = () => nodes > MAX_NODES || size >= MAX_TEXT;
  const walk = (node, kind, depth, isSchemaMap) => {
    if (node === null || (typeof node !== 'object' && typeof node !== 'string')) return;
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) { out.truncated = true; return; }
    if (typeof node === 'string') { add(node, kind); return; }
    if (seen.has(node)) return;
    seen.add(node);
    if (Array.isArray(node)) { for (const v of node) { walk(v, kind, depth + 1, false); if (spent()) return; } return; }
    for (const [k, v] of Object.entries(node)) {
      // Property names are identifiers; one that reads like a sentence is text the model sees.
      if (/\s\S+\s/.test(k)) add(k, 'value');
      if (isSchemaMap) walk(v, kind, depth + 1, false);
      else walk(v, kind === 'value' || VALUE_KEYS.has(k) ? 'value' : 'prose', depth + 1, SCHEMA_MAPS.has(k) && kind !== 'value');
      if (spent()) return;
    }
  };
  add(t.description, 'prose');
  add(t.title, 'prose');
  walk(t.annotations, 'prose', 0, false);
  walk(t.inputSchema, 'prose', 0, false);
  walk(t.outputSchema, 'prose', 0, false);
  return out;
}

// NFKC, strip invisible characters and map look-alike letters, keeping a map from
// each output position back to the original text so evidence windows line up.
function normalizeForMatch(text) {
  const clean = text.replace(EMOJI_JOINS, (m) => ' '.repeat(m.length));
  let norm = '';
  const map = [];
  const changed = [];
  let i = 0;
  for (const ch of clean) {
    const at = i;
    i += ch.length;
    if (INVISIBLE_ONE.test(ch)) continue;
    const n = CONFUSABLE[ch] ?? ch.normalize('NFKC');
    const diff = n !== ch;
    for (let k = 0; k < n.length; k++) { norm += n[k]; map.push(at); changed.push(diff && /[A-Za-z<>]/.test(n[k])); }
  }
  map.push(i);
  return { norm, map, changed };
}

function hasInvisible(text) {
  const clean = text.replace(/^﻿/, '').replace(EMOJI_JOINS, '');
  return new RegExp(INVISIBLE.source, 'u').test(clean);
}

function decodeBase64Text(s) {
  try {
    const out = Buffer.from(s, 'base64').toString('utf8');
    if (out.length < 16 || out.includes('�')) return null;
    const printable = out.match(/[\x20-\x7E\n\r\t -￿]/g)?.length ?? 0;
    return printable / out.length >= 0.95 && /[A-Za-z]{3,}\s+[A-Za-z]{2,}/.test(out) ? out : null;
  } catch { return null; }
}

/**
 * Find poisoning signals in a list of text segments.
 * @returns {{full: string, hits: {label: string, kind: string, start: number, end: number}[]}}
 */
function findSignals(segments, nested = false, allTheft = false) {
  const full = segments.map((s) => s.text).join('\n');
  const bounds = [];
  let pos = 0;
  for (const s of segments) { bounds.push([pos, pos + s.text.length, s.kind]); pos += s.text.length + 1; }
  const kindAt = (idx) => {
    let lo = 0; let hi = bounds.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (bounds[mid][1] < idx) lo = mid + 1; else hi = mid; }
    return bounds[lo]?.[2] ?? 'prose';
  };
  const { norm, map, changed } = normalizeForMatch(full);
  const hits = [];
  let lookalike = null;
  // Every match is kept, not only the first few, so a flood of harmless matches cannot
  // push the one that matters (a file next to an upload) out of the list.
  const record = (index, length, label, kind) => {
    const start = map[index];
    const end = map[index + length] ?? full.length;
    // A credential path in a default or enum is what an SSH or cloud tool legitimately carries.
    if (kind === 'target' && kindAt(start) === 'value') return;
    hits.push({ label, kind, start, end });
    if (!lookalike && changed.slice(index, index + length).some(Boolean)) lookalike = { start, end };
  };
  for (const [i, [re, label, kind]] of POISON.entries()) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    let m;
    while ((m = g.exec(norm))) {
      if (!m[0]) { g.lastIndex++; continue; }
      // "Pass its contents in the privateKey parameter" puts a key where a key belongs.
      if (credentialName(m.groups?.param)) continue;
      record(m.index, m[0].length, label, kind);
    }
    // Comments come right after hidden tags, so the reasons keep their usual order.
    if (i === 0) for (const c of findComments(norm)) record(c.start, c.end - c.start, COMMENT_LABEL, 'inject');
  }
  if (lookalike) hits.push({ label: 'look-alike characters', kind: 'obfusc', ...lookalike });
  for (const theft of findTheft(norm, allTheft ? 20 : 1)) {
    hits.push({ label: theft.dest ? 'sends secrets to an outside address' : 'smuggles data through a parameter', kind: 'steal',
      start: map[theft.start], end: map[theft.end] ?? full.length });
  }
  const secret = SECRET_DATA.exec(norm);
  if (secret) hits.push({ label: 'targets secrets or conversation data', kind: 'secrets', start: map[secret.index], end: map[secret.index + secret[0].length] ?? full.length });
  if (hasInvisible(full)) {
    const m = new RegExp(INVISIBLE.source, 'u').exec(full.replace(EMOJI_JOINS, (x) => ' '.repeat(x.length)));
    hits.push({ label: 'invisible Unicode characters', kind: 'obfusc', start: m?.index ?? 0, end: (m?.index ?? 0) + 1 });
  }
  if (nested) return { full, hits };

  // Text hidden in Unicode tag characters or base64 is decoded and scanned again.
  const hidden = [];
  // Real flags are blanked first (same length, so indexes still line up).
  for (const m of full.replace(EMOJI_JOINS, (x) => ' '.repeat(x.length)).matchAll(TAG_TEXT)) {
    hidden.push({ text: String.fromCharCode(...[...m[0]].map((c) => c.codePointAt(0) - 0xE0000)), start: m.index, end: m.index + m[0].length });
  }
  let blob = null;
  for (const m of norm.matchAll(BASE64_RUN)) {
    const start = map[m.index];
    const end = map[m.index + m[0].length] ?? full.length;
    const text = decodeBase64Text(m[0]);
    if (text) hidden.push({ text, start, end });
    else if (m[0].length >= 120 && !blob && kindAt(start) !== 'value') blob = { start, end };
  }
  let decoded = false;
  for (const h of hidden) {
    const inner = findSignals([{ text: h.text, kind: 'prose' }], true).hits.filter((x) => x.kind !== 'secrets');
    if (!inner.length) continue;
    decoded = true;
    const strong = inner.some((x) => x.kind !== 'target');
    hits.push({ label: strong ? 'instructions hidden in encoded text' : 'encoded text names sensitive files', kind: strong ? 'encoded' : 'obfusc', start: h.start, end: h.end });
  }
  if (blob && !decoded) hits.push({ label: 'long encoded blob', kind: 'blob', ...blob });
  return { full, hits };
}

// Whether a hit of kind a lies within gap characters of a hit of kind b. Sorted search, so
// thousands of hits stay cheap.
function nearKinds(hits, a, b, gap) {
  const B = hits.filter((h) => h.kind === b).sort((x, y) => x.start - y.start);
  if (!B.length) return false;
  let longest = 0;
  for (const y of B) longest = Math.max(longest, y.end - y.start);
  for (const x of hits) {
    if (x.kind !== a) continue;
    for (let i = firstStartingAt(B, x.start - gap - longest); i < B.length && B[i].start - x.end <= gap; i++) if (x.start - B[i].end <= gap) return true;
  }
  return false;
}

// Severity scales with the evidence: one weak signal is low, one manipulative signal
// is medium (high for concealment), and critical needs a combination that points at
// stealing data or hiding actions, or an outright instruction override.
function poisonSeverity(kinds, hits = []) {
  const k = (x) => kinds.has(x);
  const real = [...kinds].filter((x) => x !== 'secrets');
  if (!real.length) return null;
  if (k('override') || k('encoded') || k('steal')) return 'critical';
  if (k('exfil') && (k('target') || k('conceal') || k('inject') || k('secrets') || k('obfusc') || k('precall') || k('dest'))) return 'critical';
  // An address next to a credential file ("curl -d @~/.netrc https://...") is theft. An HTTP,
  // mail or webhook tool that names its own API key or password as configuration is not,
  // so secret nouns alone no longer escalate an address, and a file must be close by.
  const near = (a, b, gap) => nearKinds(hits, a, b, gap);
  if (k('dest') && (near('dest', 'target', 120) || k('conceal') || k('inject'))) return 'critical';
  if (k('conceal') && (k('target') || k('inject') || k('exec') || k('precall') || k('obfusc'))) return 'critical';
  if (k('inject') && (k('target') || k('exec') || k('precall'))) return 'critical';
  if (k('precall') && k('target')) return 'critical';
  if (k('obfusc') && real.some((x) => !['obfusc', 'blob', 'target', 'dest'].includes(x))) return 'critical';
  if (k('obfusc') && (k('target') || k('dest'))) return 'high';
  if (k('exec') && k('target')) return 'high';
  if (k('conceal')) return 'high';
  if (real.some((x) => !['target', 'dest', 'blob', 'exec'].includes(x))) return 'medium';
  // Sending to an address is what HTTP, mail, SMS and webhook tools are for: it only
  // counts together with something else, never as a finding or a second weak signal.
  const weak = real.filter((x) => x !== 'dest');
  if (!weak.length) return null;
  return weak.length >= 2 ? 'medium' : 'low';
}

/**
 * Evidence for a finding: the whole text when it is short, otherwise windows around
 * each match so the offending passage is always shown.
 */
// Windows are ranked by the severity of the hits inside them, so the passage that set the
// finding's severity comes first and decoys cannot use up the budget. Ties go to the
// stronger kind of hit, then to the earlier one.
const EVIDENCE_RANK = { steal: 0, override: 0, encoded: 0, inject: 1, exfil: 1, conceal: 1, precall: 2, obfusc: 2, dest: 3, exec: 3, blob: 4, target: 5 };
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const WINDOW = 200;

function evidenceAround(full, hits, limit = 1200) {
  if (full.length <= limit) return full;
  // Hits longer than a window (an encoded blob) are few and checked one by one.
  const sorted = hits.filter((h) => h.end - h.start <= 1000).sort((x, y) => x.start - y.start);
  const long = hits.filter((h) => h.end - h.start > 1000);
  const localSeverity = (a, b) => {
    const inside = long.filter((h) => h.start < b && h.end > a);
    for (let i = firstStartingAt(sorted, a - 1000); i < sorted.length && sorted[i].start < b && inside.length < 200; i++) {
      if (sorted[i].end > a) inside.push(sorted[i]);
    }
    return SEVERITY_RANK[poisonSeverity(new Set(inside.map((h) => h.kind)), inside)] ?? 4;
  };
  const ranked = sorted.filter((h) => h.kind in EVIDENCE_RANK)
    .map((h) => {
      const a = Math.max(0, h.start - WINDOW);
      const b = Math.min(full.length, h.end + WINDOW);
      return { sev: localSeverity(a, b), rank: EVIDENCE_RANK[h.kind], a, b };
    })
    .sort((x, y) => x.sev - y.sev || x.rank - y.rank || x.a - y.a);
  if (!ranked.length) return `${full.slice(0, limit)} ...`;
  const chosen = [];
  let total = 0;
  for (const w of ranked) {
    // A window inside one already chosen costs nothing; the first window is always kept whole.
    if (chosen.some((c) => w.a >= c.a && w.b <= c.b)) continue;
    if (chosen.length && total + (w.b - w.a) > limit + 300) continue;
    chosen.push(w);
    total += w.b - w.a;
    if (total >= limit + 300) break;
  }
  chosen.sort((x, y) => x.a - y.a);
  const merged = [];
  for (const { a, b } of chosen) {
    const last = merged[merged.length - 1];
    if (last && a <= last[1]) last[1] = Math.max(last[1], b);
    else merged.push([a, b]);
  }
  return merged.map(([a, b]) => `${a > 0 ? '... ' : ''}${full.slice(a, b)}${b < full.length ? ' ...' : ''}`).join('\n');
}

/**
 * The passages of a text that tool-poisoning rules matched, for highlighting in reports:
 * pattern matches, instructions in comments and theft instructions.
 * @returns {{start: number, end: number, label: string, kind: string}[]} sorted by position
 */
export function poisonSpans(text) {
  if (!text) return [];
  const { hits } = findSignals([{ text: String(text), kind: 'prose' }], true, true);
  return hits.filter((h) => h.kind !== 'secrets' && h.label !== 'invisible Unicode characters' && h.end > h.start)
    .map(({ start, end, label, kind }) => ({ start, end, label, kind }))
    .sort((x, y) => x.start - y.start || y.end - x.end);
}

/** Order spans by how much they matter, for a short "found:" list. */
export function spanRank(kind) { return EVIDENCE_RANK[kind] ?? 6; }

const TOO_LARGE = 'too large to check fully';

function analyzeSegments(segments, truncated = false) {
  const { full, hits } = findSignals(segments);
  const kinds = new Set(hits.map((h) => h.kind));
  let severity = poisonSeverity(kinds, hits);
  const showSecrets = kinds.has('exfil') || kinds.has('steal');
  const reasons = severity ? [...new Set(hits.filter((h) => h.kind !== 'secrets' || showSecrets).map((h) => h.label))] : [];
  // Text past the size limits was never read, so a clean result would be a guess.
  if (truncated) {
    reasons.push(TOO_LARGE);
    if (!severity || severity === 'low') severity = 'medium';
  }
  return { full, hits, severity, reasons };
}

/** The reasons a piece of text looks like tool poisoning (empty when it looks clean). */
export function analyzeDescription(text) {
  if (!text) return [];
  return analyzeSegments([{ text: String(text).replace(/[ \t]+/g, ' ').trim(), kind: 'prose' }]).reasons;
}

/** Severity MCS016 would give this text, or null when it looks clean. */
export function poisonSeverityOf(text) {
  if (!text) return null;
  return analyzeSegments([{ text: String(text).replace(/[ \t]+/g, ' ').trim(), kind: 'prose' }]).severity;
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// A pattern for "this text refers to the tool named `name`". Identifier-like names
// (send_message, get-library-docs, listChats) count on their own, also inside the
// prefixed forms clients use (mcp__whatsapp__send_message). Plain words such as
// query, search or fetch only count when the text clearly means a tool.
function toolRefPattern(name) {
  const n = esc(name);
  const prefix = String.raw`(?:mcp_{1,2}[\w-]+?_{1,2})`;
  if (/[_\-.]|[a-z][A-Z]|\d/.test(name)) return new RegExp(String.raw`(?<![\w-])${prefix}?${n}(?![\w-])`);
  const notParam = String.raw`(?!\s+(?:parameters?|params?|arguments?|args?|fields?|options?|propert(?:y|ies)|keys?|values?|methods?|endpoints?|strings?|statements?|requests?|results?))`;
  return new RegExp([
    String.raw`(?<![\w-])${prefix}${n}(?![\w-])`,
    String.raw`(?<!\b(?:this|a|an)\s+)[\x60'"]?\b${n}\b[\x60'"]?\s+tool\b`,
    String.raw`\btool\s+(?:called\s+|named\s+)?[\x60'"]?${n}\b${notParam}`,
    String.raw`\b(?:call|invoke|calling|invoking)\s+(?:the\s+)?[\x60'"]?${n}\b[\x60'"]?${notParam}`,
    String.raw`[\x60'"]?\b${n}\b[\x60'"]?\s+(?:is|are|gets)\s+(?:called|invoked|used)\b`,
  ].join('|'));
}

const IMPERATIVE = /\b(?:must|always|never|instead|make sure|change|set|replace|redirect|append|add|bcc|cc|forward|send)\b/i;

function sentenceAround(text, start, end) {
  let a = start;
  let b = end;
  while (a > 0 && start - a < 160 && !/[.!?\n]/.test(text[a - 1])) a--;
  while (b < text.length && b - end < 160 && !/[.!?\n]/.test(text[b])) b++;
  return text.slice(a, Math.min(text.length, b + 1)).trim();
}

// Values a live server was started with (its env, its arguments) that look
// random enough to be credentials, whatever their key is called: a server
// that echoes its own key into a tool description must not get it printed.
const randomValue = (v) => typeof v === 'string' && v.length >= 12 && !/\s/.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v)
  && entropy(v) >= 3 && !isPlaceholder(v) && !looksLikeSetting(v, '');

/**
 * @param {{server: string, tools: {name: string, description?: string, inputSchema?: any}[], secrets?: string[]}[]} toolSets
 * @param {object} [serverByName]
 * @param {object} [known] a secretIndex() of the secrets in the scanned configs
 */
export function checkTools(toolSets, serverByName = {}, known = null) {
  const out = [];
  // Tool text is printed as the model sees it, but with credentials masked:
  // known formats, credential flags and query values, every secret of the
  // scanned configs and the values the server itself was started with.
  const shown = (text, own) => {
    if (text == null) return text;
    const t = maskString(String(text), { known });
    return own ? maskKnown(t, own) : t;
  };
  const owner = new Map();
  const serverOf = new Map();
  // A live server can send anything as a name; only real strings take part in name matching.
  const named = (t) => typeof t?.name === 'string' && t.name !== '';
  for (const set of toolSets) for (const t of set.tools) if (named(t) && !serverOf.has(t.name)) serverOf.set(t.name, set.server);

  for (const set of toolSets) {
    const srv = set.srv || serverByName[set.server] || { name: set.server, client: null, file: set.file || null, jsonPath: null };
    const ctx = { server: srv };
    const ownSecrets = secretIndex((set.secrets || []).filter(randomValue));
    const show = (text) => shown(text, ownSecrets);
    const own = new Set(set.tools.filter(named).map((x) => x.name));
    for (const t of set.tools) {
      if (!t || typeof t !== 'object') continue;
      // Still check the text of a tool with a missing or odd name, under a printable label.
      const name = named(t) ? t.name : (typeof t.name === 'number' || typeof t.name === 'boolean' ? String(t.name) : '(unnamed)');
      const segments = toolTexts(t);
      const { full, hits, severity, reasons } = analyzeSegments(segments, segments.truncated);
      if (severity) {
        const f = finding('MCS016', ctx, show(`Tool "${name}": ${reasons.join(', ')}.`), { severity, evidence: show(evidenceAround(full, hits)), jsonPath: `tools.${name}` });
        if (severity !== 'critical') f.fix = 'Read the description and confirm the flagged text is legitimate before trusting this server. If it gives the model instructions that have nothing to do with the tool, remove the server and report it to the maintainer.';
        if (reasons.length === 1 && segments.truncated) f.fix = 'This tool\'s description and schema are larger or more deeply nested than mcpsafe reads, so the rest was not checked. Ordinary tools are far smaller. Review the full tool definition by hand before trusting this server.';
        out.push(f);
      }
      if (!named(t)) continue;

      // Cross-server references: the description talks about another server's tool.
      // Only prose is checked; an enum value that happens to equal a tool name is not a reference.
      const prose = normalizeForMatch(segments.filter((s) => s.kind === 'prose').map((s) => s.text).join('\n')).norm;
      const urgent = ['override', 'conceal', 'exfil', 'steal', 'inject', 'encoded'].some((x) => hits.some((h) => h.kind === x));
      let refers = false;
      for (const [other, otherServer] of serverOf) {
        if (own.has(other) || other.length < 4) continue;
        const m = toolRefPattern(other).exec(prose);
        if (!m) continue;
        refers = true;
        const sentence = sentenceAround(prose, m.index, m.index + m[0].length);
        const high = urgent || IMPERATIVE.test(sentence);
        out.push(finding('MCS017', ctx, show(high
          ? `Tool "${t.name}" gives instructions about "${other}", a tool from server "${otherServer}".`
          : `Tool "${t.name}" mentions "${other}", a tool from server "${otherServer}".`),
        { severity: high ? 'high' : 'medium', evidence: show(sentence).slice(0, 400) }));
      }

      // Same tool name on several servers. Most clients prefix tools with the server name,
      // so on its own this is a low note; it matters more when either tool is suspicious.
      const suspicious = refers || (severity && severity !== 'low');
      const prev = owner.get(t.name);
      if (prev && prev.server !== set.server) {
        const sev = suspicious || prev.suspicious ? 'medium' : 'low';
        out.push(finding('MCS017', ctx, `Tool "${t.name}" is also provided by "${prev.server}". Clients that list tools without the server name may call the wrong one${sev === 'medium' ? ', and one of the two tools also has suspicious text' : ''}.`, { severity: sev, evidence: t.name }));
      } else if (!prev) owner.set(t.name, { server: set.server, suspicious });
    }
  }
  return out;
}

// ---------------- Runner ----------------

// Records a check that failed on unexpected input as an error of its config
// file, so the reports say the scan is incomplete and the other servers and
// files are still checked.
function checkFailed(config, what, e) {
  const msg = `Could not check ${what}: ${maskText(String(e?.message ?? e).slice(0, 200))}`.replace(/[\x00-\x1f\x7f]/g, ' ');
  if (process.env.MCPSAFE_DEBUG) console.error(e);
  if (config.error?.includes(msg)) return;
  config.error = config.error ? `${config.error}; ${msg}` : msg;
}

function safely(config, what, fn) {
  try { return fn() || []; } catch (e) { checkFailed(config, what, e); return []; }
}

export function runChecks(configs) {
  const findings = [];
  for (const config of configs) {
    const fileFindings = [];
    for (const server of config.servers || []) {
      const ctx = { server, config };
      const name = String(server?.name ?? '').slice(0, 80);
      for (const check of SERVER_CHECKS) {
        for (const f of safely(config, `server "${name}"`, () => check(ctx))) {
          if (server.disabled && f.id !== 'MCS001') { f.severity = downgrade(f.severity); f.message += ' (server is disabled)'; }
          fileFindings.push(f);
        }
      }
    }
    const ctx = { config };
    fileFindings.push(...safely(config, 'the file', () => checkFileUnicode(ctx)), ...safely(config, 'the client settings', () => checkClientSettings(ctx)));
    fileFindings.push(...safely(config, 'the comments', () => checkCommentSecrets(ctx)));
    fileFindings.push(...safely(config, 'the file permissions', () => checkFilePermissions(ctx, fileFindings)));
    findings.push(...fileFindings);
  }
  // A secret found anywhere in the scanned configs is hidden wherever another
  // finding repeats it without the context that marks it (a bare argument
  // inside sh -c, a version string), in every output format.
  const known = knownSecrets(configs);
  if (known) {
    for (const f of findings) {
      f.message = maskKnown(f.message, known);
      if (typeof f.evidence === 'string') f.evidence = maskKnown(f.evidence, known);
    }
  }
  return findings;
}

/**
 * Every secret found in the text of the given configs, as a secretIndex() for
 * the `known` option of src/mask.js, or null when there is none.
 */
export function knownSecrets(configs) {
  const all = new Set();
  for (const c of configs || []) for (const x of configSecretList(c?.text)) all.add(x);
  return secretIndex(all);
}

export function displayPath(p) {
  if (!p) return p;
  const cwd = process.cwd();
  if (p.startsWith(cwd + path.sep)) return path.relative(cwd, p);
  const home = os.homedir();
  return p.startsWith(home + path.sep) ? `~${p.slice(home.length)}` : p;
}
