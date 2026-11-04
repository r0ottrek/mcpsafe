// Round 2 regression tests for the server and file rules: MCS015 on ordinary
// writing, name-only MCS007, MCS013 neighbours, wrong-typed config values,
// and the close variants left after round 1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { runChecks, typosquatOf, typosquatMatch, hiddenCharacters } from '../src/checks.js';
import { parseDockerRun } from '../src/packages.js';
import { scan } from '../src/scan.js';
import { FAKE, server, tmpdir, writeJson } from './helpers.js';

const config = (servers, extra = {}) => ({ source: { path: '/x/mcp.json', client: 'Test', scope: extra.scope || 'user' }, text: extra.text ?? '', doc: extra.doc ?? null, servers, mode: 0o600 });
const run = (defs, extra = {}) => runChecks([config(Object.entries(defs).map(([n, d]) => Object.assign(server(d, n), { scope: extra.scope || 'user' })), extra)]);
const pick = (findings, id) => findings.filter((f) => f.id === id);
const has = (findings, id, sev) => findings.some((f) => f.id === id && (!sev || f.severity === sev));
const unicode = (text) => pick(runChecks([config([], { text })]), 'MCS015');
// An opaque token with no vendor prefix, assembled at runtime.
const TOKEN = FAKE.generic + 'Hf0Gj4Ws8Nc1';

const ZWSP = '\u200B';
const ZWNJ = '\u200C';
const ZWJ = '\u200D';

test('MCS015: emoji joiners and joiners in Persian and Indic words are ordinary text', () => {
  const texts = {
    emoji: `{"display": "pairing with a dev \u{1F469}${ZWJ}\u{1F4BB} today"}`,
    skinTone: `{"display": "\u{1F469}\u{1F3FD}${ZWJ}\u{1F52C} lab"}`,
    family: `{"window.title": "\${rootName} \u{1F468}${ZWJ}\u{1F469}${ZWJ}\u{1F467}"}`,
    rainbowFlag: `{"note": "\u{1F3F3}\uFE0F${ZWJ}\u{1F308}"}`,
    englandFlag: `{"note": "\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}"}`,
    persian: `{"display": "\u0645\u06CC${ZWNJ}\u062E\u0648\u0627\u0647\u0645"}`,
    hindi: `{"display": "\u0915\u094D${ZWJ}\u0937 \u0915\u094D${ZWNJ}\u0937"}`,
    hebrewMark: `{"display": "\u05E9\u05DC\u05D5\u05DD\u200F 123"}`,
    bom: '\uFEFF{"a": "b"}',
  };
  for (const [name, text] of Object.entries(texts)) assert.deepEqual(unicode(text), [], name);
});

test('MCS015: zero-width characters inside keys, commands, arguments and URLs, and bidi or tag characters anywhere', () => {
  const texts = {
    key: `{"mcpServers": {"a": {"comm${ZWSP}and": "npx"}}}`,
    command: `{"command": "np${ZWJ}x"}`,
    argEdge: `{"args": ["${ZWSP}--allow-all"]}`,
    url: `{"url": "https://mcp.example.org${ZWNJ}/mcp"}`,
    run: `{"display": "\u0645\u06CC${ZWNJ}${ZWSP}\u062E"}`,
    override: `{"display": "\u05E9\u05DC\u05D5\u05DD \u202Etxt.exe"}`,
    isolate: `{"display": "hello \u2066world\u2069"}`,
    tags: `{"description": "ok\u{E0049}\u{E0067}\u{E006E}"}`,
    innerBom: `{"a": "b\uFEFFc"}`,
  };
  for (const [name, text] of Object.entries(texts)) {
    const f = unicode(text);
    assert.equal(f.length, 1, name);
    assert.equal(f[0].severity, 'high', name);
  }
  assert.match(unicode(`{\n"a": "b",\n"c": "d${ZWSP}e"}`)[0].message, /^1 invisible character\(s\) found, first on line 3\./);
});

test('MCS015 scan stays linear on 200KB of adversarial text', () => {
  const N = 200_000;
  const inputs = [
    ZWSP.repeat(N),
    `a${ZWSP}`.repeat(N / 2),
    `\u{1F469}${ZWJ}`.repeat(N / 3),
    `\u{1F3F4}${'\u{E0067}'.repeat(N / 2)}`,
    `\u0645${ZWNJ}`.repeat(N / 2),
    `\uFE0F${ZWJ}`.repeat(N / 2),
  ];
  for (const text of inputs) {
    const t0 = performance.now();
    hiddenCharacters(text);
    const ms = performance.now() - t0;
    assert.ok(ms < 200, `${ms.toFixed(0)}ms`);
  }
});

test('MCS007: a shell-like server name on its own is medium and says that only the name matched', () => {
  const f = run({
    'terminal-shop': { type: 'http', url: 'https://mcp.terminal.shop/mcp' },
    'shell-docs': { url: 'https://docs.example.com/mcp' },
    'terminal-docs': { command: 'node', args: ['./tools/terminal-docs-mcp/index.js'] },
    'desktop-commander': { command: 'node', args: ['./dc/index.js'] },
  });
  const shell = pick(f, 'MCS007');
  assert.equal(shell.length, 4);
  for (const x of shell) assert.equal(x.severity, 'medium', x.server);
  const remote = shell.find((x) => x.server === 'terminal-shop');
  assert.match(remote.message, /remote server at mcp\.terminal\.shop/);
  assert.match(remote.message, /"terminal" in the name/);
  assert.match(remote.message, /Only the name matched/);
  assert.match(shell.find((x) => x.server === 'desktop-commander').message, /"desktop-commander" in the name/);
  // A launched shell package is still high, whatever the server is called.
  assert.ok(has(run({ tools: { command: 'npx', args: ['-y', '@wonderwhy-er/desktop-commander@0.2.3'] } }), 'MCS007', 'high'));
  assert.ok(has(run({ shell: { command: 'npx', args: ['-y', '@wonderwhy-er/desktop-commander@0.2.3'] } }), 'MCS007', 'high'));
  assert.equal(pick(run({ shell: { command: 'npx', args: ['-y', '@wonderwhy-er/desktop-commander@0.2.3'] } }), 'MCS007').length, 1);
  assert.ok(!has(run({ docs: { url: 'https://docs.example.com/mcp' } }), 'MCS007'));
});

test('MCS007: Claude Code started through node with the path to its cli.js', () => {
  for (const p of ['/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js', 'C:\\Users\\a\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js']) {
    assert.ok(has(run({ v18: { command: 'node', args: [p, 'mcp', 'serve'] } }), 'MCS007', 'high'), p);
    assert.ok(!has(run({ v18: { command: 'node', args: [p, 'mcp', 'list'] } }), 'MCS007'), p);
  }
  assert.ok(has(run({ c: { command: 'node', args: ['/opt/node_modules/@openai/codex/bin/codex.js', 'mcp-server'] } }), 'MCS007', 'high'));
});

test('MCS013: a real package is never a typosquat, a dropped scope is medium, a misspelling stays high', () => {
  assert.equal(typosquatOf('playwright-mcp'), null);
  assert.equal(typosquatOf('playwright-mcp', 'npm'), null);
  assert.ok(!has(run({ pw: { command: 'npx', args: ['-y', 'playwright-mcp@0.0.19'] } }), 'MCS013'));
  assert.deepEqual(typosquatMatch('stripe-mcp', 'npm'), { popular: '@stripe/mcp', kind: 'scope' });
  const scope = pick(run({ s: { command: 'npx', args: ['-y', 'stripe-mcp@1.0.0'] } }), 'MCS013');
  assert.equal(scope.length, 1);
  assert.equal(scope[0].severity, 'medium');
  assert.match(scope[0].message, /without its scope/);
  assert.ok(has(run({ p: { command: 'npx', args: ['-y', '@playwrigth/mcp@0.0.40'] } }), 'MCS013', 'high'));
  // An unscoped copy of a reference server is not a community port.
  assert.ok(has(run({ g: { command: 'npx', args: ['-y', 'modelcontextprotocol-server-postgres@1.0.0'] } }), 'MCS013', 'high'));
  // npx-launched misspellings of PyPI server names, which npm has seen squatted.
  for (const spec of ['mcp-server-fecth@1.0.0', 'mcp-server-gti@1.0.0']) {
    assert.ok(has(run({ a: { command: 'npx', args: ['-y', spec] } }), 'MCS013', 'high'), spec);
  }
  assert.ok(!has(run({ a: { command: 'npx', args: ['-y', 'mcp-server-gsc@0.3.0'] } }), 'MCS013'));
  assert.equal(typosquatOf(null), null);
  assert.equal(typosquatOf(['mcp-server-fetch']), null);
});

test('wrong-typed values never crash the checks', () => {
  const odd = [['http://evil.example.com/mcp'], 42, { a: 1 }, null, true, ''];
  for (const field of ['url', 'command', 'cwd', 'env', 'headers']) {
    for (const v of odd) {
      const s = server({ command: 'npx', args: ['-y', 'x-mcp@1.0.0'] }, 'a');
      s[field] = v;
      const cfg = config([s]);
      assert.doesNotThrow(() => runChecks([cfg]), `${field}=${JSON.stringify(v)}`);
      assert.equal(cfg.error, undefined, `${field}=${JSON.stringify(v)}`);
    }
  }
  const s = server({ command: 'node', args: ['a.js'], env: { A: 1, B: null, C: ['x'], D: { e: 1 } }, headers: { Authorization: ['Bearer x'] } }, 'a');
  assert.doesNotThrow(() => runChecks([config([s])]));
  assert.doesNotThrow(() => parseDockerRun(['run', null, 5, { a: 1 }, 'mcp/x:1.0']));
  assert.doesNotThrow(() => parseDockerRun(null));
});

test('an unexpected exception in one server becomes a config error and the scan goes on', () => {
  const bad = server({ command: 'npx', args: [] }, 'bad');
  Object.defineProperty(bad, 'args', { get() { throw new Error('boom'); } });
  const good = server({ command: 'npx', args: ['-y', 'firecrawl-mcp'] }, 'good');
  const other = config([server({ command: 'npx', args: ['-y', 'mcp-remote'] }, 'other')]);
  const cfg = config([bad, good]);
  const f = runChecks([cfg, other]);
  assert.equal(cfg.error, 'Could not check server "bad": boom');
  assert.ok(f.some((x) => x.server === 'good' && x.id === 'MCS003'));
  assert.ok(f.some((x) => x.server === 'other' && x.id === 'MCS003'));
});

test('a server whose url is an array does not stop the scan or the reports', async () => {
  const dir = tmpdir();
  writeJson(path.join(dir, '.mcp.json'), { mcpServers: { s: { url: ['http://evil.example.com/mcp'] }, ok: { command: 'npx', args: ['-y', 'firecrawl-mcp'] } } });
  const r = await scan({ paths: [dir], includeHome: false, home: tmpdir() });
  assert.ok(r.findings.some((x) => x.server === 'ok' && x.id === 'MCS003'));
});

test('MCS005/006: mcp-remote run from an install folder', () => {
  const f = run({ r: { command: 'node', args: ['/opt/node_modules/mcp-remote/dist/proxy.js', `http://node.example.org/sse?token=${TOKEN}`] } });
  assert.ok(has(f, 'MCS005'));
  assert.equal(pick(f, 'MCS006').length, 1);
  assert.equal(pick(f, 'MCS006')[0].jsonPath, 'mcpServers.r.args[1]');
  assert.ok(!JSON.stringify(f).includes(TOKEN));
  assert.ok(has(run({ r: { command: 'node', args: ['C:\\npm\\node_modules\\mcp-remote\\dist\\proxy.js', 'http://node.example.org/sse'] } }), 'MCS005'));
  // A URL given to an ordinary script is data.
  assert.ok(!has(run({ r: { command: 'node', args: ['/opt/fetcher/index.js', 'http://docs.example.org/'] } }), 'MCS005'));
});

test('MCS006: template placeholders and names that only end in key or token', () => {
  const url = (q) => ({ a: { url: `https://mcp.example.org/mcp?${q}` } });
  for (const q of ['api_key=[YOUR_API_KEY]', 'api_key={API_KEY}', 'token=__TOKEN__', 'token={{ secrets.TOKEN }}',
    'sort_key=created_at_desc', 'page_token=nextpage2', 'auth=required', 'next_token=page-two-of-ten', 'idempotency_key=retry_once_only']) {
    assert.ok(!has(run(url(q)), 'MCS006'), q);
  }
  for (const q of [`api_key=${TOKEN}`, `token=${TOKEN}`, `auth=${TOKEN}`, `github_token=${FAKE.github}`, `service_key=${TOKEN}`,
    `client_secret=${TOKEN}`, `page_token=x&access_token=${TOKEN}`]) {
    assert.ok(has(run(url(q)), 'MCS006'), q);
  }
});

test('MCS006 stays linear on 200KB query strings', () => {
  for (const q of [`api_key=${'{{'.repeat(100_000)}`, `${'a_'.repeat(100_000)}key=${TOKEN}`, `token=__${'a_'.repeat(100_000)}`, `auth=${'ab1'.repeat(66_000)}`]) {
    const t0 = performance.now();
    run({ a: { url: `https://mcp.example.org/mcp?${q}` } });
    const ms = performance.now() - t0;
    assert.ok(ms < 200, `${ms.toFixed(0)}ms`);
  }
});

test('MCS004/008/009: podman value flags and the short -v forms', () => {
  for (const flag of ['--authfile', '--image-volume', '--env-merge', '--hostuser', '--hosts-file', '--health-on-failure', '--health-startup-cmd',
    '--shm-size-systemd', '--signature-policy', '--preserve-fd', '--health-log-destination', '--systemd']) {
    const f = run({ p: { command: 'podman', args: ['run', '-i', '--rm', flag, '/a.json', '--privileged', 'mcp/x:1.0'] } });
    assert.ok(has(f, 'MCS009'), flag);
    assert.ok(!has(f, 'MCS004'), flag);
  }
  // An unknown option whose value cannot be an image does not hide the rest.
  const u = run({ p: { command: 'podman', args: ['run', '--some-new-flag', '/etc/x.conf', '--privileged', 'mcp/x:1.0'] } });
  assert.ok(has(u, 'MCS009'));
  assert.ok(!has(u, 'MCS004'));
  assert.equal(parseDockerRun(['run', '--init', 'mcp/x:1.0']).image, 'mcp/x:1.0');
  for (const args of [['run', '-i', '-v/:/host', 'mcp/x:1.0'], ['run', '-itv', '/:/host', 'mcp/x:1.0'], ['run', '-v=/:/host', 'mcp/x:1.0']]) {
    const f = run({ d: { command: 'docker', args } });
    assert.ok(has(f, 'MCS008'), args.join(' '));
    assert.ok(!has(f, 'MCS004'), args.join(' '));
  }
  assert.deepEqual(parseDockerRun(['run', '-it', '--rm', '-eFOO=bar', 'img:1']), { image: 'img:1', flags: [['-i', true], ['-t', true], ['--rm', true], ['-e', 'FOO=bar']] });
});

test('docker image detection stays linear on a 200KB argument', () => {
  for (const a of ['a'.repeat(200_000), `a${'/a:1'.repeat(50_000)}`, `${'a.'.repeat(100_000)}/`]) {
    const t0 = performance.now();
    parseDockerRun(['run', '--unknown', a, 'img:1']);
    const ms = performance.now() - t0;
    assert.ok(ms < 200, `${ms.toFixed(0)}ms`);
  }
});

test('MCS014: values of node options are not the script', () => {
  for (const flag of ['--env-file', '--env-file-if-exists', '--watch-path', '--title', '--input-type', '-C']) {
    assert.ok(!has(run({ a: { command: 'node', args: [flag, '/tmp/x', 'server.js'] } }), 'MCS014'), flag);
  }
  assert.ok(has(run({ a: { command: 'node', args: ['--env-file', '.env', '/tmp/server.js'] } }), 'MCS014'));
  assert.ok(has(run({ a: { command: 'npx', args: ['tsx', '/tmp/server.ts'] } }), 'MCS014'));
});

test('MCS001: a secret in `command` is found also when `args` is not empty', () => {
  for (const [command, args] of [[`npx -y some-mcp --api-key ${FAKE.anthropic}`, ['--verbose']], [`npx --api-key ${FAKE.anthropic}`, ['-y', 'some-mcp']]]) {
    const f = pick(run({ a: { command, args } }, { scope: 'project' }), 'MCS001');
    assert.equal(f.length, 1, command);
    assert.equal(f[0].jsonPath, 'mcpServers.a.command');
    assert.ok(!JSON.stringify(f).includes(FAKE.anthropic));
  }
  // Repeated in args, the same secret is reported once.
  assert.equal(pick(run({ a: { command: `npx --api-key ${FAKE.anthropic}`, args: ['--api-key', FAKE.anthropic] } }), 'MCS001').length, 1);
});

test('MCS008: a local build of the filesystem server started through a runner package', () => {
  const f = run({ tsx: { command: 'npx', args: ['tsx', '/Users/alice/src/servers/src/filesystem/index.ts', '/Users/alice'] } });
  const fs = pick(f, 'MCS008');
  assert.equal(fs.length, 1);
  assert.match(fs[0].message, /"\/Users\/alice"/);
  assert.ok(!fs[0].message.includes('index.ts'));
  assert.ok(!has(run({ tsx: { command: 'npx', args: ['tsx', '/Users/alice/src/other/index.ts', '/Users/alice'] } }), 'MCS008'));
});
