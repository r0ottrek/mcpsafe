// Tests for --connect (src/live.js and the connect loop in src/scan.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir, writeJson, server, FAKE } from './helpers.js';
import { listTools, expandVars, spawnPlan, projectRoot, MAX_PAGES } from '../src/live.js';
import { extractServers } from '../src/parse.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'mcpsafe.js');
const fixture = path.join(root, 'test/fixtures/live-server.js');
const { startHttpServer } = await import('./fixtures/live-http.js');

const run = (args, opts = {}) => {
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [bin, ...args], {
    encoding: 'utf8', cwd: opts.cwd || root, timeout: opts.timeout || 60000, env: { ...process.env, NO_COLOR: '1', ...opts.env },
  });
  r.elapsed = Date.now() - t0;
  return r;
};
const stdio = (mode, extra = {}, name = 'srv') => server({ command: process.execPath, args: [fixture, mode, ...(extra.args || [])], env: extra.env, cwd: extra.cwd }, name);
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Finding: a stdio server that exits at once crashed the CLI with EPIPE.
test('a server that exits at once is reported, not a crash', async () => {
  for (let i = 0; i < 3; i++) {
    await assert.rejects(listTools(server({ command: process.execPath, args: ['-e', 'process.exit(1)'] })), /exited with code 1/);
  }
  const dir = tmpdir();
  writeJson(path.join(dir, '.mcp.json'), { mcpServers: {
    a: { command: process.execPath, args: ['-e', 'process.exit(1)'] },
    b: { command: 'sh', args: ['-c', 'exit 1'] },
    c: { command: process.execPath, args: [fixture, 'normal'] },
  } });
  const r = run(['--no-home', dir, '--connect', '--json']);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.liveErrors.length, 2);
  assert.ok(out.liveErrors.every((e) => /exited with code 1/.test(e.error)));
  assert.equal(out.toolsScanned, 1);
});

// Finding: the CLI never exited when a server ignored SIGTERM.
test('a server that ignores stdin EOF and SIGTERM is killed and the CLI exits', () => {
  const dir = tmpdir();
  const pidfile = path.join(dir, 'pid');
  writeJson(path.join(dir, '.mcp.json'), { mcpServers: { s: { command: process.execPath, args: [fixture, 'ignoreterm'], env: { PIDFILE: pidfile } } } });
  const r = run(['--no-home', dir, '--connect', '--json'], { timeout: 30000 });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.elapsed < 10000, `took ${r.elapsed}ms`);
  assert.equal(JSON.parse(r.stdout).toolsScanned, 1);
  const pid = Number(fs.readFileSync(pidfile, 'utf8'));
  assert.equal(alive(pid), false, 'server process should be gone');
});

test('a hanging stdio server times out and is killed', async () => {
  const dir = tmpdir();
  const pidfile = path.join(dir, 'pid');
  await assert.rejects(listTools(stdio('hang', { env: { PIDFILE: pidfile } }), 500), /timed out/);
  const pid = Number(fs.readFileSync(pidfile, 'utf8'));
  await sleep(400);
  assert.equal(alive(pid), false);
});

// Finding: HTTP requests were not aborted on timeout, and open SSE streams were read to the end.
test('an HTTP server that never answers is aborted at the timeout', async () => {
  const h = await startHttpServer();
  const t0 = Date.now();
  await assert.rejects(listTools(server({ url: `${h.base}/hang` }, 'h'), 500), /timed out/);
  assert.ok(Date.now() - t0 < 2000);
  // close() waits for open connections, so it only resolves if the request was aborted.
  await Promise.race([h.close(), sleep(3000).then(() => assert.fail('connection left open'))]);
});

test('an SSE response that stays open is read as soon as the response arrives', async () => {
  const h = await startHttpServer();
  const t0 = Date.now();
  const tools = await listTools(server({ url: `${h.base}/sseopen` }, 'h'), 5000);
  assert.equal(tools.length, 1);
  assert.ok(Date.now() - t0 < 2000);
  await Promise.race([h.close(), sleep(3000).then(() => assert.fail('connection left open'))]);
});

// Finding: ${VAR} references were not expanded.
test('expandVars handles ${VAR}, ${env:VAR}, ${VAR:-default}, and leaves unknown references', () => {
  const ctx = { env: { A: 'aa', EMPTY: '' }, home: '/home/u', workspace: '/w', unresolved: new Set(), secrets: new Set() };
  assert.equal(expandVars('${A}-${env:A}-${A:-x}-${EMPTY:-def}-${NOPE:-d${A}}', ctx), 'aa-aa-aa-def-d${A}');
  assert.equal(expandVars('${userHome}/x ${workspaceFolder}', ctx), '/home/u/x /w');
  assert.equal(expandVars('${input:key} ${MISSING}', ctx), '${input:key} ${MISSING}');
  assert.deepEqual([...ctx.unresolved], ['${input:key}', '${MISSING}']);
  assert.deepEqual([...ctx.secrets], ['aa']);
});

test('env, args, header and url references are expanded from the environment', async () => {
  const token = FAKE.generic;
  process.env.MCPSAFE_TEST_TOKEN = token;
  process.env.MCPSAFE_TEST_ARG = 'hello';
  try {
    let tools = await listTools(stdio('needtoken', { env: { TOKEN: '${MCPSAFE_TEST_TOKEN}', EXPECTED: token } }));
    assert.equal(tools.length, 1);
    tools = await listTools(stdio('needtoken', { env: { TOKEN: '${MCPSAFE_TEST_UNSET:-' + token + '}', EXPECTED: token } }));
    assert.equal(tools.length, 1);
    tools = await listTools(stdio('argv', { args: ['${MCPSAFE_TEST_ARG}', '${env:MCPSAFE_TEST_ARG}'] }));
    assert.deepEqual(JSON.parse(tools[0].name), ['hello', 'hello']);

    const h = await startHttpServer({ expected: token });
    process.env.MCPSAFE_TEST_BASE = h.base;
    try {
      tools = await listTools(server({ url: '${MCPSAFE_TEST_BASE}/auth', headers: { Authorization: 'Bearer ${env:MCPSAFE_TEST_TOKEN}' } }, 'h'));
      assert.equal(tools.length, 1);
      await assert.rejects(listTools(server({ url: '${MCPSAFE_TEST_NOPE}/json' }, 'h')), /URL refers to a variable that is not set.*\$\{MCPSAFE_TEST_NOPE\}/);
    } finally {
      delete process.env.MCPSAFE_TEST_BASE;
      await h.close();
    }

    // A wrong value: the server echoes it, but the error masks it.
    await assert.rejects(listTools(stdio('needtoken', { env: { TOKEN: '${MCPSAFE_TEST_TOKEN}', EXPECTED: 'other' } })), (e) => {
      assert.ok(!e.message.includes(token), e.message);
      assert.match(e.message, /refused/);
      return true;
    });
    // An unresolved reference is named in the error.
    await assert.rejects(listTools(stdio('needtoken', { env: { TOKEN: '${input:api-key}', EXPECTED: token } })), /not set: \$\{input:api-key\}/);
  } finally {
    delete process.env.MCPSAFE_TEST_TOKEN;
    delete process.env.MCPSAFE_TEST_ARG;
  }
});

// Finding: project servers ran in the wrong folder, and disabledMcpjsonServers was ignored.
test('project servers start in the project folder, from any current folder', () => {
  const dir = tmpdir();
  fs.mkdirSync(path.join(dir, 'server'));
  fs.copyFileSync(fixture, path.join(dir, 'server', 'index.js'));
  fs.writeFileSync(path.join(dir, 'marker.txt'), 'x');
  writeJson(path.join(dir, '.mcp.json'), { mcpServers: { local: { command: process.execPath, args: ['server/index.js', 'cwd'] } } });
  writeJson(path.join(dir, '.cursor/mcp.json'), { mcpServers: { cur: { command: process.execPath, args: ['server/index.js', 'cwd'] } } });
  const elsewhere = tmpdir();
  const out = JSON.parse(run(['--no-home', dir, '--connect', '--json'], { cwd: elsewhere }).stdout);
  assert.deepEqual(out.liveErrors, []);
  assert.equal(out.toolsScanned, 2);
});

test('projectRoot and cwd settings', async () => {
  assert.equal(projectRoot({ scope: 'project', file: '/p/.vscode/mcp.json', jsonPath: 'servers.x' }), '/p');
  assert.equal(projectRoot({ scope: 'project', file: '/p/.mcp.json', jsonPath: 'mcpServers.x' }), '/p');
  assert.equal(projectRoot({ scope: 'user', file: '/h/.claude.json', jsonPath: 'projects["/w/app"].mcpServers.x' }), '/w/app');
  assert.equal(projectRoot({ scope: 'user', file: '/h/.cursor/mcp.json', jsonPath: 'mcpServers.x' }), null);
  // A server's own cwd setting is used.
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, 'marker.txt'), 'x');
  assert.equal((await listTools(stdio('cwd', { cwd: dir }))).length, 1);
  await assert.rejects(listTools(stdio('cwd', { cwd: path.join(dir, 'missing') })), /does not exist/);
});

test('servers turned off with disabledMcpjsonServers are not started', () => {
  const home = tmpdir();
  const proj = path.join(home, 'proj');
  const log = path.join(home, 'log');
  writeJson(path.join(proj, '.mcp.json'), { mcpServers: {
    pm: { command: process.execPath, args: [fixture, 'normal'], env: { LOGFILE: log } },
    on: { command: process.execPath, args: [fixture, 'argv'] },
  } });
  writeJson(path.join(home, '.claude.json'), { projects: { [proj]: { disabledMcpjsonServers: ['pm'] } } });
  const out = JSON.parse(run(['--home', home, proj, '--connect', '--json'], { cwd: proj }).stdout);
  assert.equal(fs.existsSync(log), false, 'pm must not be started');
  assert.equal(out.toolsScanned, 1);
  assert.deepEqual(out.liveErrors, []);

  // The same through the project's .claude/settings.local.json.
  const home2 = tmpdir();
  const proj2 = path.join(home2, 'proj');
  writeJson(path.join(proj2, '.mcp.json'), { mcpServers: { pm: { command: process.execPath, args: [fixture, 'normal'], env: { LOGFILE: log } } } });
  writeJson(path.join(proj2, '.claude/settings.local.json'), { disabledMcpjsonServers: ['pm'] });
  const out2 = JSON.parse(run(['--no-home', proj2, '--connect', '--json']).stdout);
  assert.equal(fs.existsSync(log), false);
  assert.equal(out2.toolsScanned, 0);
});

// Finding: live findings were attributed by server name only.
test('two configs with the same server name: findings and errors point at the right file', () => {
  const dir = tmpdir();
  const good = writeJson(path.join(dir, 'a/.cursor/mcp.json'), { mcpServers: { github: { command: process.execPath, args: [fixture, 'normal'] } } });
  const bad = writeJson(path.join(dir, 'b/.mcp.json'), { mcpServers: { github: { command: process.execPath, args: ['-e', 'process.exit(1)'] } } });
  const out = JSON.parse(run(['--no-home', dir, '--connect', '--json']).stdout);
  const poison = out.findings.find((f) => f.id === 'MCS016');
  assert.equal(poison.file, good);
  assert.equal(out.liveErrors.length, 1);
  assert.equal(out.liveErrors[0].file, bad);
  assert.equal(out.liveErrors[0].server, 'github');
});

// Finding: Windows spawn with shell:true re-parsed arguments.
test('Windows: .cmd shims go through cmd.exe with every argument quoted and escaped', () => {
  const files = new Set(['C:\\Program Files\\nodejs\\npx.cmd', 'C:\\Program Files\\nodejs\\node.exe', 'C:\\p\\node_modules\\.bin\\srv.cmd']);
  const env = { Path: 'C:\\Windows;"C:\\Program Files\\nodejs"', PATHEXT: '.COM;.EXE;.BAT;.CMD', ComSpec: 'C:\\Windows\\system32\\cmd.exe' };
  const opts = { platform: 'win32', env, exists: (p) => files.has(p) };

  const exe = spawnPlan('node', ['C:\\Users\\John Doe\\srv.js', 'Q&A notes'], opts);
  assert.deepEqual(exe, { file: 'C:\\Program Files\\nodejs\\node.exe', args: ['C:\\Users\\John Doe\\srv.js', 'Q&A notes'], verbatim: false });

  const cmd = spawnPlan('npx', ['-y', 'pkg@1.0.0', 'C:\\My Files\\', 'a&b|c', 'say "hi"', '%PATH%'], opts);
  assert.equal(cmd.file, 'C:\\Windows\\system32\\cmd.exe');
  assert.equal(cmd.verbatim, true);
  assert.deepEqual(cmd.args.slice(0, 3), ['/d', '/s', '/c']);
  assert.equal(cmd.args[3], '"C:\\Program^ Files\\nodejs\\npx.cmd ^"-y^" ^"pkg@1.0.0^" ^"C:\\My^ Files\\\\^" ^"a^&b^|c^" ^"say^ \\^"hi\\^"^" ^"^%PATH^%^""');

  // npm cmd-shims re-parse their arguments, so metacharacters are escaped twice.
  const shim = spawnPlan('C:\\p\\node_modules\\.bin\\srv', ['a&b'], opts);
  assert.equal(shim.args[3], '"C:\\p\\node_modules\\.bin\\srv.cmd ^^^"a^^^&b^^^""');

  // Not Windows: unchanged, no shell.
  assert.deepEqual(spawnPlan('npx', ['a b'], { platform: 'linux' }), { file: 'npx', args: ['a b'], verbatim: false });
});

// Finding: Gemini CLI `url` is an SSE endpoint.
test('Gemini CLI url is SSE, httpUrl and type http are Streamable HTTP', () => {
  const gem = { client: 'Gemini CLI', path: '/p/.gemini/settings.json', scope: 'project' };
  const s = extractServers({ mcpServers: {
    a: { url: 'http://h/sse' }, b: { httpUrl: 'http://h/mcp' }, c: { url: 'http://h/mcp', type: 'http' }, d: { url: 'http://h/sse', httpUrl: 'http://h/mcp' },
  } }, gem);
  assert.deepEqual(s.map((x) => [x.name, x.transport, x.url]), [['a', 'sse', 'http://h/sse'], ['b', 'http', 'http://h/mcp'], ['c', 'http', 'http://h/mcp'], ['d', 'http', 'http://h/mcp']]);
  const cur = extractServers({ mcpServers: { a: { url: 'http://h/mcp' }, b: { url: 'http://h/sse', transportType: 'sse' } } }, { client: 'Cursor', path: '/p/.cursor/mcp.json', scope: 'project' });
  assert.deepEqual(cur.map((x) => x.transport), ['http', 'sse']);
});

test('the older HTTP+SSE transport is supported, and used as a fallback', async () => {
  const h = await startHttpServer();
  try {
    let tools = await listTools({ ...server({ url: `${h.base}/legacy` }, 'g'), transport: 'sse' }, 5000);
    assert.equal(tools.length, 1);
    // Configured as Streamable HTTP: the POST gets 405, so the SSE transport is tried.
    tools = await listTools(server({ url: `${h.base}/legacy` }, 'g'), 5000);
    assert.equal(tools.length, 1);
    // An endpoint on another host is refused, so headers never go there.
    await assert.rejects(listTools({ ...server({ url: `${h.base}/legacy-away`, headers: { Authorization: 'Bearer x' } }, 'g'), transport: 'sse' }, 5000), /different host/);
  } finally {
    await h.close();
  }
});

// Finding: protocol handling gaps.
test('a server request that reuses a request id is answered, not taken as the response', async () => {
  const tools = await listTools(stdio('pingfirst'), 5000);
  assert.equal(tools.length, 1);
  const h = await startHttpServer();
  try {
    assert.equal((await listTools(server({ url: `${h.base}/reqfirst` }, 'h'), 5000)).length, 1);
  } finally {
    await h.close();
  }
});

test('the negotiated protocol version is sent, and multi-line SSE data is joined', async () => {
  const h = await startHttpServer();
  try {
    assert.equal((await listTools(server({ url: `${h.base}/strictproto` }, 'h'), 5000)).length, 1);
    assert.equal((await listTools(server({ url: `${h.base}/multiline` }, 'h'), 5000)).length, 1);
    assert.equal((await listTools(server({ url: `${h.base}/sse` }, 'h'), 5000)).length, 1);
  } finally {
    await h.close();
  }
});

test('a cut-off tool list is reported', async () => {
  const tools = await listTools(stdio('manypages'), 20000);
  assert.equal(tools.length, MAX_PAGES);
  assert.match(tools.warning, /first 100 pages/);
  const again = await listTools(stdio('samecursor'), 5000);
  assert.equal(again.length, 2);
  assert.match(again.warning, /repeated/);

  const dir = tmpdir();
  writeJson(path.join(dir, '.mcp.json'), { mcpServers: { many: { command: process.execPath, args: [fixture, 'manypages'] } } });
  const out = JSON.parse(run(['--no-home', dir, '--connect', '--json']).stdout);
  assert.equal(out.toolsScanned, MAX_PAGES);
  assert.ok(out.findings.some((f) => f.id === 'MCS016' && /page25/.test(f.message)));
  assert.match(out.liveErrors[0].error, /pages/);
});
