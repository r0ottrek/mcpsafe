// Round 3, mask-secrets: masking reads arguments with the same parser as
// MCS001 (secrets.js argValues), so whatever MCS001 reports is hidden in every
// output; fewer false negatives in the secret rules; no secret text in JSON
// parse errors; and every scan stays linear on 200KB of hostile input.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir, writeJson, server } from './helpers.js';
import { argValues, detectInArg, findSecrets, looksLikeEnvName } from '../src/secrets.js';
import { maskArgv, maskString, secretsOfArgv } from '../src/mask.js';
import { maskText as maskConfig } from '../src/locate.js';
import { runChecks } from '../src/checks.js';
import { parseJsonc } from '../src/jsonc.js';
import { splitCommandLine, splitCommandLineSpans } from '../src/packages.js';
import { listTools } from '../src/live.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'mcpsafe.js');
const run = (args) => {
  const env = { ...process.env, NO_COLOR: '1' };
  delete env.FORCE_COLOR;
  return spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', cwd: root, env, timeout: 60000 });
};

const ALNUM = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
const opaque = (n = 30) => [...crypto.randomBytes(n)].map((b) => ALNUM[b % ALNUM.length]).join('');
const pick = (alphabet, n) => [...crypto.randomBytes(n)].map((b) => alphabet[b % alphabet.length]).join('');
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';

function assertHidden(text, secrets, where) {
  for (const s of secrets) {
    const piece = s.slice(Math.floor(s.length / 2) - 6, Math.floor(s.length / 2) + 6);
    assert.ok(!text.includes(s), `${where}: full secret ${s.slice(0, 4)}... is shown`);
    assert.ok(!text.includes(piece), `${where}: part of secret ${s.slice(0, 4)}... is shown`);
  }
}

// Argument shapes that MCS001 reports. Each builds the args for one secret.
const SHAPES = {
  digitFlag: (g) => ['--2fa-secret', g],
  digitEq: (g) => [`--2fa-secret=${g}`],
  underFlag: (g) => ['--_api_key', g],
  longFlag: (g) => [`--${'a'.repeat(70)}-token`, g],
  longEq: (g) => [`--${'a'.repeat(70)}-api-key=${g}`],
  longHdr: (g) => ['--header', `X-${'a'.repeat(70)}-Api-Key: ${g}`],
  spaceColon: (g) => ['--header', `x-api-key : ${g}`],
  spaceColonTight: (g) => ['--header', `x-api-key :${g}`],
  eqHeaderSpace: (g) => [`--header=x-api-key : ${g}`],
  tabColon: (g) => ['--header', `X-Api-Key\t:\t${g}`],
};

test('every argument shape MCS001 reports is masked by maskArgv and in config excerpts', () => {
  const servers = {};
  const secrets = {};
  for (const [name, build] of Object.entries(SHAPES)) {
    secrets[name] = opaque();
    servers[name] = { command: 'npx', args: ['-y', 'x-mcp@1.0.0', ...build(secrets[name])] };
  }
  const g = opaque();
  servers.cmdLine = { command: `npx -y mcp-remote@1.0.0 https://x.example.com/mcp --header "x-api-key : ${g}"` };
  secrets.cmdLine = g;
  const text = JSON.stringify({ mcpServers: servers }, null, 2);
  const cfg = { source: { path: '/p/.mcp.json', client: 'Claude Code', scope: 'project' }, text, servers: [] };
  cfg.servers = Object.entries(servers).map(([n, d]) => ({ ...server(d, n), scope: 'project', file: '/p/.mcp.json', client: 'Claude Code' }));
  const findings = runChecks([cfg]).filter((f) => f.id === 'MCS001');
  for (const name of Object.keys(secrets)) {
    assert.ok(findings.some((f) => f.server === name), `MCS001 reports ${name}`);
  }
  const masked = maskConfig(text);
  assert.equal(masked.split('\n').length, text.split('\n').length);
  for (const [name, s] of Object.entries(secrets)) {
    assertHidden(masked, [s], `excerpt ${name}`);
    const d = servers[name];
    const argv = [d.command, ...(d.args || [])];
    assertHidden(maskArgv(argv).join(' '), [s], `maskArgv ${name}`);
    assert.ok(secretsOfArgv(argv).some((x) => x.includes(s) || s.includes(x)), `secretsOfArgv ${name}`);
  }
  assertHidden(JSON.stringify(findings), Object.values(secrets), 'findings');
});

test('the shared argument parser reads arguments the way MCS001 always did', () => {
  assert.deepEqual(argValues('--api-key=abc', ''), [{ key: 'api-key', value: 'abc', offset: 10 }]);
  assert.deepEqual(argValues('abc', '--2fa'), [{ key: '2fa', value: 'abc', offset: 0 }]);
  assert.deepEqual(argValues('X-Key : v1', '--header'), [{ key: 'header', value: 'X-Key : v1', offset: 0 }, { key: 'X-Key', value: 'v1', offset: 8 }]);
  // A URL is never read as a header.
  assert.equal(argValues('https://a.example.com:8443/x', '').length, 1);
  const g = opaque();
  assert.ok(detectInArg(`X-Api-Key : ${g}`, '--header'));
  assert.equal(detectInArg('--port=8080', ''), null);
  // splitCommandLine and the spans masking uses are the same split.
  const line = `npx -y "a b" 'c d' e\\ f --k="x y" g`;
  assert.deepEqual(splitCommandLineSpans(line).map((w) => w.text), splitCommandLine(line));
  for (const w of splitCommandLineSpans(line)) assert.ok(line.slice(w.start, w.end).length >= w.text.length);
});

test('masking does not hide ordinary arguments', () => {
  for (const argv of [
    ['npx', '-y', '@modelcontextprotocol/server-filesystem@1.0.0', '/home/me/projects'],
    ['node', 'server.js', '--port', '8080', '--log-level=debug'],
    ['npx', 'mcp-remote@1.0.0', 'https://mcp.example.com/sse', '--header', 'Accept: text/event-stream'],
    ['uvx', 'mcp-server-git@1.0.0', '--repository', '/srv/repo'],
  ]) assert.deepEqual(maskArgv(argv), argv);
  assert.equal(maskString('npx -y x-mcp@1.0.0 --name 2fa-helper'), 'npx -y x-mcp@1.0.0 --name 2fa-helper');
});

test('live error messages mask "Name : value" headers and digit-first flags', async () => {
  const dir = tmpdir();
  const srv = path.join(dir, 'echo.mjs');
  fs.writeFileSync(srv, `import readline from 'node:readline';
const tok = process.argv.slice(2).join(' ');
readline.createInterface({ input: process.stdin }).on('line', (l) => {
  const m = JSON.parse(l);
  if (m.id != null) process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, error: { code: -32000, message: 'rejected ' + tok } }) + '\\n');
});
`);
  const a = opaque();
  const b = opaque();
  const c = opaque();
  const err = await listTools(server({ command: process.execPath, args: [srv, '--header', `X-Api-Key : ${a}`, '--2fa-secret', b, `--_api_key=${c}`] })).catch((e) => e);
  assert.ok(err instanceof Error);
  assert.match(err.message, /rejected/);
  assertHidden(err.message, [a, b, c], 'live error');
});

test('-v and HTML hide digit-first flags, long keys and "Name : value" headers', () => {
  const dir = tmpdir();
  const home = tmpdir();
  const secrets = {};
  const servers = {};
  for (const [name, build] of Object.entries(SHAPES)) {
    secrets[name] = opaque();
    servers[name] = { command: 'npx', args: ['-y', 'x-mcp@1.0.0', ...build(secrets[name])] };
  }
  writeJson(path.join(dir, '.mcp.json'), { mcpServers: servers });
  const html = path.join(home, 'r.html');
  const v = run(['--no-home', '--home', home, dir, '--no-color', '-v', '--html', html]);
  const j = run(['--no-home', '--home', home, dir, '--json']);
  assert.ok(JSON.parse(j.stdout).findings.filter((f) => f.id === 'MCS001').length >= Object.keys(SHAPES).length);
  assertHidden(v.stdout + v.stderr, Object.values(secrets), '-v');
  assertHidden(fs.readFileSync(html, 'utf8'), Object.values(secrets), 'html');
  assertHidden(j.stdout, Object.values(secrets), 'json');
});

// ---- secret rules: false negatives ----

test('random capitals joined by underscores are not taken for variable names', () => {
  assert.ok(findSecrets('ABCD1234_EFGH5678_IJKL9012', 'API_KEY').length);
  assert.ok(findSecrets('UPKJSE_7A1Z79_C2LK2N_QHUS5S', 'API_KEY').length);
  assert.ok(findSecrets('S0FXJW_TYJCIQ_1737SP_KDN9GK', 'DB_PASSWORD').length);
  let missed = 0;
  for (let i = 0; i < 400; i++) {
    const v = Array.from({ length: 4 }, () => pick(UPPER + DIGITS, 6)).join('_');
    const w = Array.from({ length: 4 }, () => pick(UPPER, 5)).join('_');
    for (const k of ['API_KEY', 'DB_PASSWORD', 'CLIENT_SECRET', 'ACCESS_TOKEN']) {
      if (!findSecrets(v, k).length) missed++;
      if (!findSecrets(w, k).length) missed++;
    }
  }
  assert.ok(missed <= 8, `${missed} of 3200 missed`);
  // Real variable names are still not secrets.
  assert.ok(looksLikeEnvName('GITHUB_PERSONAL_ACCESS_TOKEN'));
  for (const [k, v] of [['API_KEY', 'OPENAI_API_KEY'], ['token-env-var', 'GITHUB_PERSONAL_ACCESS_TOKEN'], ['SECRET_KEY_ENV', 'DJANGO_SECRET_KEY']]) {
    assert.deepEqual(findSecrets(v, k), [], `${k}=${v}`);
  }
});

test('license-style groups of capitals are not taken for ordinary words', () => {
  assert.ok(findSecrets('GBRLE-NROXA-FNUYV-RFQFS', 'API_KEY').length);
  assert.ok(findSecrets('QWER12-ASDF34-ZXCV56-POIU78', 'API_KEY').length);
  let missed = 0;
  for (let i = 0; i < 500; i++) {
    const a = Array.from({ length: 4 }, () => pick(UPPER, 5)).join('-');
    const b = Array.from({ length: 4 }, () => pick(UPPER, 4) + pick(DIGITS, 2)).join('-');
    if (!findSecrets(a, 'API_KEY').length) missed++;
    if (!findSecrets(b, 'API_KEY').length) missed++;
  }
  assert.ok(missed <= 5, `${missed} of 1000 missed`);
  // Identifiers and scope lists made of words are still settings.
  for (const v of ['Mail.Read,User.Read,Files.ReadWrite', 'secrets/GCP/SA-Reader2', 'read:user,repo,gist', 'azure-active-directory']) {
    assert.deepEqual(findSecrets(v, 'CLIENT_SECRET'), [], v);
  }
});

test('the local dev database exemption checks every host', () => {
  const pw = ['ad', 'min'].join('');
  for (const v of [
    `mongodb://${pw}:${pw}@localhost:27017,db2.prod.acme.com:27017/x`,
    'postgresql://postgres:postgres@localhost,prod.acme.com:5432/db',
    'postgresql://postgres:postgres@localhost:5432/db?host=prod.acme.com',
    'postgresql://postgres:postgres@localhost:5432/db?sslmode=disable&hostaddr=10.1.2.3',
  ]) assert.ok(findSecrets(v, '').length, v);
  for (const v of [
    `mongodb://${pw}:${pw}@localhost:27017,127.0.0.1:27018/x?replicaSet=rs0`,
    'postgresql://postgres:postgres@127.0.0.1:54322/postgres',
    'postgresql://postgres:postgres@[::1]:5432/db',
  ]) assert.deepEqual(findSecrets(v, ''), [], v);
});

test('the host rule needs a plausible host name and skips password keys', () => {
  assert.ok(findSecrets('Xk9mQ2pL7vR4tY8w.Ab', 'SECRET').length);
  assert.ok(findSecrets('Login.MicrosoftOnline.com', 'PASSWORD').length);
  assert.deepEqual(findSecrets('Login.MicrosoftOnline.com', 'CLIENT_SECRET'), []);
  assert.deepEqual(findSecrets('login.microsoftonline.com', 'AUTH_TOKEN'), []);
  assert.deepEqual(findSecrets('vault.internal.acme.de', 'SECRET'), []);
  assert.ok(findSecrets('prod.k9x2m7q4z8w1.abc', 'API_KEY').length);
});

// ---- parse errors and stderr ----

test('JSON parse errors quote no part of the config text', () => {
  const g = opaque();
  for (const text of [`{"mcpServers":{"a":{"env":{"API_KEY":${g}}}}}`, `{\n  "a": 1,\n  "b": ${g}\n}`, g, `{"x": [${g}]}`]) {
    let msg = '';
    try { parseJsonc(text); } catch (e) { msg = e.message; }
    assert.ok(msg, 'parse fails');
    assert.ok(!msg.includes(g.slice(0, 5)), `message shows part of the value: ${msg.replace(g.slice(0, 5), '#####')}`);
    assert.ok(!msg.includes(g.slice(1, 6)));
  }
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, '.mcp.json'), `{"mcpServers":{"a":{"env":{"API_KEY":${g}}}}}`);
  const r = run(['--no-home', '--home', tmpdir(), dir, '--json']);
  const out = r.stdout + r.stderr;
  assert.match(out, /Could not parse JSON/);
  assert.ok(!out.includes(g.slice(0, 5)) && !out.includes(g.slice(2, 7)));
});

test('the --min-score error escapes control characters', () => {
  const r = run(['--no-home', '--min-score', 'x\u001b[2J']);
  assert.equal(r.status, 2);
  assert.ok(!r.stderr.includes('\u001b'));
  assert.match(r.stderr, /--min-score must be a number/);
});

// ---- linear time ----

test('detection and masking stay linear on 200KB of hostile input', () => {
  const N = 200000;
  const fill = (unit) => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  const units = [
    '-----BEGIN PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----\n', 'postgres://a:postgres@', 'mongodb://a:admin@localhost,',
    'postgres://a:postgres@localhost?host=', 'x-api-key : ', ' : ', 'X : ', '--2', '--_', '_', 'A_', 'AB_', 'ABCDE-', 'a.B.', 'A.b.',
    'a.co/', `--${'a'.repeat(50)}=`, `${'a'.repeat(30)}: `, '\\ ', '\\"', '"', "'", ' a', '--token ', `--api-key ${'Zq8Lm2RtVx9P'} `,
  ];
  for (const u of units) {
    const s = fill(u);
    const runs = {
      find: () => findSecrets(s, 'API_KEY'),
      findPw: () => findSecrets(s, 'PASSWORD'),
      arg: () => detectInArg(s, '--token'),
      split: () => splitCommandLineSpans(s),
      mask: () => maskString(s),
      maskKey: () => maskString(s, { key: 'api_key', prev: '--header' }),
      argv: () => maskArgv(['--2fa-secret', s]),
      parse: () => { try { parseJsonc(s); } catch { /* expected */ } },
    };
    for (const [name, fn] of Object.entries(runs)) {
      let best = Infinity;
      for (let i = 0; i < 2; i++) {
        const t0 = performance.now();
        fn();
        best = Math.min(best, performance.now() - t0);
      }
      assert.ok(best < 300, `${JSON.stringify(u)} ${name}: ${best.toFixed(0)} ms`);
    }
  }
});

test('the argument, variable name and host rules are linear on their own', () => {
  const N = 200000;
  const fill = (unit) => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  for (const u of ['a', '-', '--a', 'a=', ':', 'a : ', ' ', 'a.', 'A_', 'A0_', '_A', 'a.bb.', 'x-y:', '\n', '--a=b\n', 'a: b\n']) {
    for (const s of [fill(u), `${fill(u)}!`, `--${fill(u)}`, `A${fill(u)}.com:`]) {
      const t0 = performance.now();
      argValues(s, '--x');
      argValues(`--k=${s}`, '');
      looksLikeEnvName(s);
      findSecrets(s, 'SECRET');
      assert.ok(performance.now() - t0 < 150, `${JSON.stringify(u)}: ${(performance.now() - t0).toFixed(0)} ms`);
    }
  }
});
