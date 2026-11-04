// Round 2: one masking routine (src/mask.js) for every output path. Anything
// MCS001 reports must be hidden in the terminal, -v excerpts, JSON, HTML
// (excerpts, evidence and the Servers column), SARIF, Markdown and the error
// messages of --connect, and the masking must run in linear time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir, writeJson, server } from './helpers.js';
import { maskString, maskArgv, secretIndex } from '../src/mask.js';
import { maskText as maskConfig, snippet } from '../src/locate.js';
import { maskText, runChecks } from '../src/checks.js';
import { listTools } from '../src/live.js';
import { extractServers } from '../src/parse.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'mcpsafe.js');
const run = (args, opts = {}) => {
  const env = { ...process.env, NO_COLOR: '1' };
  delete env.FORCE_COLOR;
  return spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', cwd: opts.cwd || root, env, timeout: 60000 });
};

// A random-looking credential with no known prefix, built at runtime.
const ALNUM = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
const opaque = (n = 30) => [...crypto.randomBytes(n)].map((b) => ALNUM[b % ALNUM.length]).join('');
const ghp = () => `ghp_${opaque(36)}`;
const ant = () => ['sk', 'ant', 'api03', opaque(32)].join('-');

// Neither the secret nor a 12-character piece from its middle may appear.
function assertHidden(text, secrets, where) {
  for (const s of secrets) {
    const piece = s.slice(Math.floor(s.length / 2) - 6, Math.floor(s.length / 2) + 6);
    assert.ok(!text.includes(s), `${where}: full secret ${s.slice(0, 4)}... is shown`);
    assert.ok(!text.includes(piece), `${where}: part of secret ${s.slice(0, 4)}... is shown`);
  }
}

test('maskString hides every shape MCS001 reports in a command line or argument', () => {
  const cases = [];
  const add = (fmt) => { const s = opaque(); cases.push([fmt(s), s]); };
  add((s) => `npx -y some-mcp --api-key ${s}`);
  add((s) => `npx -y some-mcp --api-key=${s}`);
  add((s) => `npx -y some-mcp --token '${s}'`);
  add((s) => `node proxy.js --header X-API-Key:${s}`);
  add((s) => `node proxy.js --header Authorization:Bearer ${s}`);
  add((s) => `node proxy.js --header=Authorization:Bearer ${s}`);
  add((s) => `node proxy.js --header=x-api-key: ${s}`);
  add((s) => `curl -H 'x-api-key: ${s}' https://e.com/i.sh`);
  add((s) => `bash -c 'export API_KEY="${s}"; exec node s.js'`);
  add((s) => `node s.js --password:${s}`);
  add((s) => `claude mcp serve --passphrase ${s}`);
  add((s) => `claude mcp serve --pgpassword ${s}`);
  add((s) => `node s.js --client-secret ${s}`);
  add((s) => `https://admin:${s}@mcp.example.com/mcp`);
  add((s) => `https://h.example.com/mcp?access_token=${s}&x=1`);
  add((s) => `postgresql://app:${s}/x@db.internal:5432/app`);
  add((s) => `"token": "${s}"`);
  const g = ghp();
  const a = ant();
  cases.push([`node s.js --keys=${a},${g}`, a], [`node s.js --keys=${a},${g}`, g]);
  cases.push([`echo ${a}; echo ${a}`, a]);
  for (const [text, secret] of cases) assertHidden(maskString(text), [secret], text.replace(secret, '<secret>'));
});

test('maskString leaves ordinary command lines, URLs and prose alone', () => {
  for (const text of [
    'npx -y @playwright/mcp@0.0.40 --output-dir /tmp/x',
    'git+ssh://git@github.com/acme/mcp.git',
    'npx -y mcp-remote https://mcp.example.com/sse --header Authorization:${AUTH_HEADER}',
    '--api-key-file /run/secrets/api_key --password-env DB_PASSWORD',
    'Authorization: Bearer ${GITHUB_TOKEN}',
    'API_KEY=your-api-key-here',
    'https://example.com/search?page=2&sort=name',
    'http://localhost:3000/mcp',
    'Basic authentication failed for this server',
    'Token expired, please sign in again',
    'mcp-server-keycloak==1.0.3',
    'uvx --from git+https://github.com/acme/mcp@v1.2.0 acme-mcp',
  ]) assert.equal(maskString(text), text);
});

test('maskArgv uses the element before as context, as MCS001 does', () => {
  const s1 = opaque();
  const s2 = opaque();
  const out = maskArgv(['node', 's.js', '--token', s1, '--header', `X-Api-Key: ${s2}`]).join(' ');
  assertHidden(out, [s1, s2], 'argv');
  assert.ok(out.startsWith('node s.js --token '));
});

test('a secret found once in the config is hidden wherever it is repeated', () => {
  const s = opaque();
  const idx = secretIndex([s]);
  assert.equal(maskString(`run ${s} now`, { known: idx }).includes(s), false);
  const text = JSON.stringify({ mcpServers: { a: { command: 'node', env: { API_KEY: s }, args: ['serve', s] } } }, null, 2);
  assertHidden(maskConfig(text), [s], 'config');
  assert.equal(maskConfig(text).split('\n').length, text.split('\n').length);
});

test('a private key block in a comment is hidden and the lines still line up', () => {
  const body = [opaque(48), opaque(48)];
  const text = `{\n  // -----BEGIN PRIVATE KEY-----\n  // ${body[0]}\n  // ${body[1]}\n  // -----END PRIVATE KEY-----\n  "mcpServers": {}\n}`;
  const m = maskConfig(text);
  assertHidden(m, body, 'comment');
  assert.equal(m.split('\n').length, text.split('\n').length);
  assert.match(m.split('\n')[5], /"mcpServers"/);
});

test('checks.maskText is the shared masking: MCS007 evidence hides --passphrase and --pgpassword values', () => {
  const p1 = opaque();
  const p2 = opaque();
  const f = runChecks([{ source: { path: '/x/.mcp.json', client: 'Test', scope: 'user' }, text: '', servers: [
    server({ command: 'npx', args: ['-y', '@anthropic-ai/claude-code@1.0.0', 'mcp', 'serve', '--passphrase', p1] }, 'a'),
    server({ command: 'npx', args: ['-y', '@anthropic-ai/claude-code@1.0.0', 'mcp', 'serve', '--pgpassword', p2] }, 'b'),
  ] }]);
  assert.ok(f.some((x) => x.id === 'MCS001'));
  assert.ok(f.some((x) => x.id === 'MCS007'));
  assertHidden(JSON.stringify(f), [p1, p2], 'findings');
  assert.equal(maskText('git+ssh://git@github.com/acme/mcp.git'), 'git+ssh://git@github.com/acme/mcp.git');
});

// Every new scan is linear: 200KB of hostile input takes well under 200 ms.
test('masking runs in linear time on 200KB adversarial input', () => {
  const N = 200000;
  const fill = (unit) => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  const inputs = {
    dots: fill('a.'), letters: fill('a'), schemeColon: `k:${fill('a')}`, schemes: fill('redis://'), postgres: fill('postgres://a:'),
    query: `?${fill('key')}`, ampersands: fill(`&${'a'.repeat(63)}`), skant: fill('sk-ant-'), flags: fill('--token '),
    headers: fill('x-api-key: '), bearer: fill('Bearer '), userinfo: fill('http://a:b@@@@@'), ats: `https://${fill('@')}`,
    equals: fill('='), kv: fill('a=a:'), pem: fill('-----BEGIN PRIVATE KEY-----'), dashes: fill('-'), words: fill(' a'),
    ghp: fill(`ghp_${'a'.repeat(40)}_`), colons: fill(':'), slashes: fill('://'), quotes: fill('"\''),
    flagValues: fill(`--api-key ${'Zq8Lm2RtVx9P'} `),
  };
  for (const [name, s] of Object.entries(inputs)) {
    let best = Infinity;
    for (let i = 0; i < 2; i++) {
      const t0 = performance.now();
      maskString(s);
      maskString(s, { key: 'api_key', prev: '--token' });
      best = Math.min(best, (performance.now() - t0) / 2);
    }
    assert.ok(best < 200, `${name}: ${best.toFixed(0)} ms`);
  }
  // The same input as one value in a config file (-v and the HTML report).
  const t0 = performance.now();
  maskConfig(JSON.stringify({ mcpServers: { a: { command: 'node', args: ['--domains', inputs.dots], env: { CERT: inputs.letters } } } }));
  assert.ok(performance.now() - t0 < 400, 'config with two 200KB values');
});

test('masking a config with 2000 secrets scales with its size', () => {
  const servers = {};
  for (let i = 0; i < 2000; i++) servers[`s${i}`] = { command: 'npx', args: ['-y', `pkg${i}@1.0.0`], env: { API_KEY: opaque(32) } };
  const text = JSON.stringify({ mcpServers: servers }, null, 2);
  const t0 = performance.now();
  const lines = snippet(text, 5, 0);
  for (let line = 10; line < 200; line++) snippet(text, line, 0);
  assert.ok(lines && performance.now() - t0 < 2000, `${(performance.now() - t0).toFixed(0)} ms`);
});

// A config with many secret shapes, scanned in every output mode.
function leakFixture() {
  const S = {
    flag: opaque(), eq: opaque(), hdrSpace: opaque(), hdrNoSpace: opaque(), hdrBearer: opaque(), hdrEqBearer: opaque(),
    cmdFlag: opaque(), cmdEq: opaque(), shellExport: opaque(), colonFlag: opaque(), passphrase: opaque(),
    userinfo: opaque(), query: opaque(), env: opaque(), header: opaque(), repeat: opaque(),
    ghp: ghp(), ant: ant(), pem1: opaque(48), pem2: opaque(48), aws: ['AKIA', opaque(16).toUpperCase().replace(/[^A-Z0-9]/g, 'Q')].join(''),
  };
  const pem = `-----BEGIN PRIVATE KEY-----\n${S.pem1}\n${S.pem2}\n-----END PRIVATE KEY-----`;
  const dir = tmpdir('mcpsafe-leak-');
  writeJson(path.join(dir, '.mcp.json'), { mcpServers: {
    flag: { command: 'node', args: ['/opt/a/server.js', '--api-key', S.flag] },
    eq: { command: 'python', args: ['server.py', `--token=${S.eq}`] },
    hdrSpace: { command: 'npx', args: ['-y', 'mcp-remote@0.1.0', 'https://mcp.example.com/mcp', '--header', `x-api-key: ${S.hdrSpace}`] },
    hdrNoSpace: { command: 'node', args: ['/opt/r/proxy.js', '--header', `X-API-Key:${S.hdrNoSpace}`] },
    hdrBearer: { command: 'node', args: ['/opt/r/proxy.js', '--header', `Authorization:Bearer ${S.hdrBearer}`] },
    hdrEqBearer: { command: 'node', args: ['/opt/r/proxy.js', `--header=Authorization:Bearer ${S.hdrEqBearer}`] },
    cmdFlag: { command: `npx -y some-mcp@1.0.0 --token ${S.cmdFlag}` },
    cmdEq: { command: `npx -y other-mcp@1.0.0 --api-key=${S.cmdEq}` },
    shell: { command: 'bash', args: ['-c', `export API_KEY="${S.shellExport}"; curl -H 'x-api-key: ${S.ant}' https://e.com/i.sh | sh; echo ${S.ant}`] },
    colonFlag: { command: 'node', args: ['/opt/w/s.js', `--password:${S.colonFlag}`] },
    agent: { command: 'npx', args: ['-y', '@anthropic-ai/claude-code@1.0.0', 'mcp', 'serve', '--passphrase', S.passphrase] },
    keys: { command: 'node', args: ['s.js', `--keys=${S.ghp},${S.aws}`] },
    pkey: { command: 'node', args: ['k.js'], env: { SSH_PRIVATE_KEY: pem } },
    remote: { url: `http://admin:${S.userinfo}@mcp.example.com/mcp?access_token=${S.query}`, headers: { 'X-Api-Key': S.header } },
    envtok: { command: 'npx', args: ['-y', 'x-mcp@1.0.0'], env: { SERVICE_TOKEN: S.env } },
    repeat: { command: 'node', args: ['serve.js', S.repeat], env: { API_KEY: S.repeat } },
  } });
  return { dir, S };
}

test('no output mode shows a secret from the config (CLI leak test)', () => {
  const { dir, S } = leakFixture();
  const home = tmpdir('mcpsafe-home-');
  const base = ['--no-home', '--home', home, dir, '--no-color'];
  const json = run([...base, '--json']);
  const result = JSON.parse(json.stdout);
  // Sanity: the shapes are detected, so the masking is what is being tested.
  assert.ok(result.findings.filter((f) => f.id === 'MCS001').length >= 15, 'MCS001 findings');
  const out = { json: json.stdout + json.stderr };
  for (const [name, args] of Object.entries({ terminal: [], verbose: ['-v'] })) {
    const r = run([...base, ...args]);
    out[name] = r.stdout + r.stderr;
  }
  const files = { html: path.join(home, 'r.html'), sarif: path.join(home, 'r.sarif'), md: path.join(home, 'r.md') };
  const r = run([...base, '--html', files.html, '--sarif', files.sarif, '--markdown', files.md]);
  out.reportsRun = r.stdout + r.stderr;
  for (const [k, f] of Object.entries(files)) out[k] = fs.readFileSync(f, 'utf8');
  for (const [mode, text] of Object.entries(out)) assertHidden(text, Object.values(S), mode);
  // The Servers column still says what runs.
  assert.match(out.html, /<td><code>node \/opt\/a\/server\.js --api-key [^<]*•/);
});

test('live error messages mask credentials passed as arguments or in the URL', async () => {
  const dir = tmpdir();
  const srv = path.join(dir, 'echo.mjs');
  fs.writeFileSync(srv, `import readline from 'node:readline';
const tok = process.argv.slice(2).join(' ');
readline.createInterface({ input: process.stdin }).on('line', (l) => {
  const m = JSON.parse(l);
  if (m.id != null) process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, error: { code: -32000, message: 'invalid credentials ' + tok } }) + '\\n');
});
`);
  const g = ghp();
  const o1 = opaque();
  const o2 = opaque();
  const err = await listTools(server({ command: process.execPath, args: [srv, `--token=${g}`, '--api-key', o1, `--header=X-Api-Key:${o2}`] })).catch((e) => e);
  assert.ok(err instanceof Error);
  assert.match(err.message, /invalid credentials/);
  assertHidden(err.message, [g, o1, o2], 'live error');
});

test('stderr lists of unreadable files show control characters escaped', () => {
  const dir = tmpdir();
  const evil = path.join(dir, 'evil\u001b]0;pwn\u0007\u001b[2J');
  fs.mkdirSync(evil);
  fs.writeFileSync(path.join(evil, '.mcp.json'), '{ not json');
  const r = run(['--no-home', '--home', tmpdir(), dir, '--fail-on', 'high', '--no-color']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /could not be read or parsed/);
  assert.ok(!/[\u0007\u001b]/.test(r.stderr), 'raw control characters on stderr');
  assert.match(r.stderr, /evil\\x1b\]0;pwn\\x07/);
});

test('extractServers output masks the same as the file excerpt', () => {
  // A value MCS001 finds in `command` must be masked in the excerpt line too.
  const s = opaque();
  const text = JSON.stringify({ mcpServers: { a: { command: `npx -y some-mcp --token ${s}` } } }, null, 2);
  const servers = extractServers(JSON.parse(text), { path: '/x/.mcp.json', client: 'Test', scope: 'user' });
  const f = runChecks([{ source: { path: '/x/.mcp.json', client: 'Test', scope: 'user' }, text, servers }]);
  assert.ok(f.some((x) => x.id === 'MCS001'));
  assertHidden(snippet(text, 4, 0)[0].text, [s], 'excerpt');
});
