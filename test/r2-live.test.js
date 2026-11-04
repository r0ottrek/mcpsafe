// Round 2 regression tests for --connect (src/live.js): process groups,
// Gemini CLI bare $VAR, symlinked projects, npx.cmd escaping and the
// negotiated protocol version.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir, writeJson, server } from './helpers.js';
import { listTools, expandVars, spawnPlan, liveGroups } from '../src/live.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'mcpsafe.js');
const fixture = path.join(root, 'test/fixtures/live-server.js');
const gcFixture = path.join(root, 'test/fixtures/grandchild-server.js');
const posix = process.platform !== 'win32';

const run = (args, opts = {}) => {
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [bin, ...args], {
    encoding: 'utf8', cwd: opts.cwd || root, timeout: opts.timeout || 60000, env: { ...process.env, NO_COLOR: '1', ...opts.env },
  });
  r.elapsed = Date.now() - t0;
  return r;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A zombie (killed, but not reaped because PID 1 in a container may not reap
// orphans) counts as gone.
function alive(pid) {
  try { process.kill(pid, 0); } catch { return false; }
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    return stat.slice(stat.lastIndexOf(')') + 2)[0] !== 'Z';
  } catch {
    return !fs.existsSync('/proc/self');
  }
}
async function waitGone(pids, ms = 4000) {
  const end = Date.now() + ms;
  while (Date.now() < end && pids.some(alive)) await sleep(50);
  return pids.filter(alive);
}
const readPid = (f) => Number(fs.readFileSync(f, 'utf8'));
const killAll = (pids) => { for (const p of pids) { try { process.kill(p, 'SIGKILL'); } catch { /* gone */ } } };

// Finding (code-review hunt, audit #29): on POSIX close() signalled only the
// direct child, so grandchildren started by a wrapper outlived the scan.
test('grandchild processes of a server are gone after a scan', { skip: !posix }, async () => {
  const dir = tmpdir();
  const f = (n) => path.join(dir, n);
  writeJson(f('.mcp.json'), { mcpServers: {
    // Exits on stdin EOF, but leaves a grandchild that ignores SIGTERM.
    quick: { command: process.execPath, args: [gcFixture, 'normal'], env: { GCPIDFILE: f('gc1') } },
    // Ignores SIGTERM itself, and so does its grandchild.
    stubborn: { command: process.execPath, args: [gcFixture, 'ignoreterm'], env: { GCPIDFILE: f('gc2'), PIDFILE: f('srv2') } },
    // A shell wrapper that does not exec: the server is a grandchild.
    wrapped: { command: 'sh', args: ['-c', `"${process.execPath}" "${fixture}" ignoreterm; true`], env: { PIDFILE: f('srv3') } },
  } });
  const r = run(['--no-home', dir, '--connect', '--json'], { timeout: 30000 });
  const pids = ['gc1', 'gc2', 'srv2', 'srv3'].map((n) => readPid(f(n)));
  try {
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.toolsScanned, 3);
    assert.deepEqual(out.liveErrors, []);
    assert.ok(r.elapsed < 10000, `took ${r.elapsed}ms`);
    assert.deepEqual(await waitGone(pids), [], 'every server process should be gone');
  } finally {
    killAll(pids);
  }
});

test('a server that leaves a grandchild does not hold the CLI open', { skip: !posix }, async () => {
  const dir = tmpdir();
  writeJson(path.join(dir, '.mcp.json'), { mcpServers: {
    quick: { command: process.execPath, args: [gcFixture, 'normal'], env: { GCPIDFILE: path.join(dir, 'gc') } },
  } });
  const r = run(['--no-home', dir, '--connect', '--json'], { timeout: 30000 });
  const pid = readPid(path.join(dir, 'gc'));
  try {
    assert.equal(r.status, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).toolsScanned, 1);
    // Well under the 2.5s SIGKILL timer: the CLI does not wait for the
    // grandchild, and the grandchild does not hold the CLI's own stdout.
    assert.ok(r.elapsed < 2400, `took ${r.elapsed}ms`);
    assert.deepEqual(await waitGone([pid]), []);
  } finally {
    killAll([pid]);
  }
});

test('listTools as a library cleans up grandchildren without the process exiting', { skip: !posix }, async () => {
  const dir = tmpdir();
  const gcfile = path.join(dir, 'gc');
  const tools = await listTools(server({ command: process.execPath, args: [gcFixture, 'normal'], env: { GCPIDFILE: gcfile } }), 10000);
  assert.equal(tools.length, 1);
  const pid = readPid(gcfile);
  try {
    assert.deepEqual(await waitGone([pid]), []);
    const end = Date.now() + 2000;
    while (liveGroups().length && Date.now() < end) await sleep(50);
    assert.deepEqual(liveGroups(), [], 'no process group is still watched');
    // Nothing is left hooked to the process once every group is gone.
    assert.equal(process.listeners('exit').some((l) => l.name === 'killAllGroups'), false);
  } finally {
    killAll([pid]);
  }
});

test('Ctrl-C during a scan ends the servers too', { skip: !posix }, async () => {
  const dir = tmpdir();
  const f = (n) => path.join(dir, n);
  writeJson(f('.mcp.json'), { mcpServers: {
    h: { command: process.execPath, args: [gcFixture, 'hang'], env: { GCPIDFILE: f('gc'), PIDFILE: f('srv') } },
  } });
  const cli = spawn(process.execPath, [bin, '--no-home', dir, '--connect', '--json'], { stdio: 'ignore' });
  const exited = new Promise((r) => cli.on('exit', (code, signal) => r({ code, signal })));
  const end = Date.now() + 10000;
  while (!(fs.existsSync(f('gc')) && fs.existsSync(f('srv'))) && Date.now() < end) await sleep(50);
  await sleep(200);
  const pids = [readPid(f('gc')), readPid(f('srv'))];
  try {
    cli.kill('SIGINT');
    const res = await exited;
    assert.equal(res.signal, 'SIGINT');
    assert.deepEqual(await waitGone(pids, 3000), []);
  } finally {
    killAll(pids);
    cli.kill('SIGKILL');
  }
});

// Audit #31: Gemini CLI also expands bare $VAR in its settings.
test('Gemini CLI: bare $VAR is expanded; other clients and unset names are left alone', () => {
  const ctx = (bare) => ({ env: { MY_TOKEN: 'tok-value-1', EMPTY: '' }, bare, unresolved: new Set(), secrets: new Set(), misses: 0 });
  const g = ctx(true);
  assert.equal(expandVars('$MY_TOKEN', g), 'tok-value-1');
  assert.equal(expandVars('a/$MY_TOKEN/b ${MY_TOKEN}', g), 'a/tok-value-1/b tok-value-1');
  assert.equal(expandVars('x$EMPTY.y', g), 'x.y');
  // Unset: kept literally, as Gemini CLI does, and not a miss (so an env value
  // like a password with a "$" in it is still passed on).
  assert.equal(expandVars('pa$sw0rd', g), 'pa$sw0rd');
  assert.equal(g.misses, 0);
  assert.ok(g.unresolved.has('$sw0rd'));
  assert.equal(expandVars('$ $1 $$ ${', g), '$ $1 $$ ${');
  assert.ok(g.secrets.has('tok-value-1'));

  const o = ctx(false);
  assert.equal(expandVars('$MY_TOKEN ${MY_TOKEN}', o), '$MY_TOKEN tok-value-1');

  const dir = tmpdir();
  const home = tmpdir();
  const env = { MY_TOKEN: ['exp', 'ected', '-value-123'].join('') };
  writeJson(path.join(dir, '.gemini/settings.json'), { mcpServers: {
    s: { command: process.execPath, args: [fixture, 'needtoken'], env: { TOKEN: '$MY_TOKEN', EXPECTED: env.MY_TOKEN } },
  } });
  const out = JSON.parse(run(['--home', home, '--no-home', '--connect', '--json', '.'], { cwd: dir, env }).stdout);
  assert.deepEqual(out.liveErrors, []);
  assert.equal(out.toolsScanned, 1);
  assert.ok(out.findings.some((x) => x.id === 'MCS016'));

  // The same in a Claude Code .mcp.json is not expanded (Claude Code does not).
  const dir2 = tmpdir();
  writeJson(path.join(dir2, '.mcp.json'), { mcpServers: {
    s: { command: process.execPath, args: [fixture, 'needtoken'], env: { TOKEN: '$MY_TOKEN', EXPECTED: env.MY_TOKEN } },
  } });
  const out2 = JSON.parse(run(['--home', home, '--no-home', '--connect', '--json', dir2], { env }).stdout);
  assert.equal(out2.toolsScanned, 0);
  assert.equal(out2.liveErrors.length, 1);
});

test('expandVars takes linear time on adversarial input', () => {
  const env = {};
  const inputs = ['${'.repeat(100000), '$'.repeat(200000), '$a'.repeat(100000), '${a'.repeat(66667), `${'${A:-'.repeat(40000)}}`];
  for (const bare of [false, true]) {
    for (const s of inputs) {
      const t0 = process.hrtime.bigint();
      expandVars(s, { env, bare, unresolved: new Set(), secrets: new Set(), misses: 0 });
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      assert.ok(ms < 200, `${JSON.stringify(s.slice(0, 6))}... bare=${bare} took ${ms}ms`);
    }
  }
});

// Audit #32: disabledMcpjsonServers was ignored when the project was scanned
// through a symlinked path.
test('disabledMcpjsonServers applies when the project is scanned through a symlink', { skip: !posix }, () => {
  const home = fs.realpathSync(tmpdir());
  const proj = path.join(home, 'proj');
  const log = path.join(home, 'log');
  writeJson(path.join(proj, '.mcp.json'), { mcpServers: {
    pm: { command: process.execPath, args: [fixture, 'normal'], env: { LOGFILE: log } },
  } });
  writeJson(path.join(home, '.claude.json'), { projects: { [proj]: { disabledMcpjsonServers: ['pm'] } } });
  const other = tmpdir();
  const link = path.join(other, 'projlink');
  fs.symlinkSync(proj, link);
  const out = JSON.parse(run(['--home', home, link, '--connect', '--json'], { cwd: other }).stdout);
  assert.equal(fs.existsSync(log), false, 'pm must not be started');
  assert.equal(out.toolsScanned, 0);

  // Control: without the setting it does start.
  writeJson(path.join(home, '.claude.json'), {});
  const out2 = JSON.parse(run(['--home', home, link, '--connect', '--json'], { cwd: other }).stdout);
  assert.equal(out2.toolsScanned, 1);
  assert.equal(fs.existsSync(log), true);
});

// Audit #35: nodejs\npx.cmd (and other .cmd/.bat files that pass %* on) parse
// their arguments a second time, so they need the double escaping too.
test('Windows: every .cmd and .bat gets its arguments escaped twice; .exe is spawned directly', () => {
  const files = new Set([
    'C:\\Program Files\\nodejs\\npx.cmd', 'C:\\Program Files\\nodejs\\node.exe',
    'C:\\Users\\me\\AppData\\Roaming\\npm\\mcp-srv.cmd', 'C:\\tools\\run.bat',
  ]);
  const env = { Path: 'C:\\Windows;C:\\Program Files\\nodejs;C:\\Users\\me\\AppData\\Roaming\\npm;C:\\tools', PATHEXT: '.COM;.EXE;.BAT;.CMD', ComSpec: 'C:\\Windows\\system32\\cmd.exe' };
  const opts = { platform: 'win32', env, exists: (p) => files.has(p) };
  const arg = '{"X-Q":"a=1&b=2"}';
  const twice = '^^^"{\\^^^"X-Q\\^^^":\\^^^"a=1^^^&b=2\\^^^"}^^^"';
  assert.equal(spawnPlan('npx', [arg], opts).args[3], `"C:\\Program^ Files\\nodejs\\npx.cmd ${twice}"`);
  assert.equal(spawnPlan('mcp-srv', [arg], opts).args[3], `"C:\\Users\\me\\AppData\\Roaming\\npm\\mcp-srv.cmd ${twice}"`);
  assert.equal(spawnPlan('run', [arg], opts).args[3], `"C:\\tools\\run.bat ${twice}"`);
  assert.deepEqual(spawnPlan('node', [arg], opts), { file: 'C:\\Program Files\\nodejs\\node.exe', args: [arg], verbatim: false });
});

// Audit #62: an unknown or invalid negotiated protocol version was accepted
// silently, and a value that is not a valid header broke the scan.
test('the negotiated protocol version is checked', async () => {
  const seen = [];
  let answer;
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const m = JSON.parse(body);
      seen.push({ method: m.method, version: req.headers['mcp-protocol-version'] });
      if (m.id === undefined) { res.writeHead(202).end(); return; }
      const result = m.method === 'initialize'
        ? { protocolVersion: answer, capabilities: { tools: {} }, serverInfo: { name: 'v', version: '1' } }
        : { tools: [{ name: 'echo', description: 'Echoes.' }] };
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result }));
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${srv.address().port}/mcp`;
  const list = async (v) => {
    answer = v;
    seen.length = 0;
    return listTools(server({ url }, 'v'), 5000);
  };
  try {
    let t = await list('1999-01-01');
    assert.equal(t.length, 1);
    assert.match(t.warning, /protocol version 1999-01-01, which is older than any MCP version/);

    t = await list('bad\nvalue');
    assert.equal(t.length, 1, 'an invalid version must not stop the scan');
    assert.match(t.warning, /invalid protocol version \("bad\\nvalue"\)/);
    assert.equal(seen.find((s) => s.method === 'tools/list').version, '2025-06-18');

    t = await list(42);
    assert.match(t.warning, /invalid protocol version \(a number\)/);

    // Newer and known versions are accepted without comment and sent back.
    for (const v of ['2099-01-01', '2025-03-26', '2024-11-05']) {
      t = await list(v);
      assert.equal(t.warning, undefined, v);
      assert.equal(seen.find((s) => s.method === 'tools/list').version, v);
    }
    // A server that does not say keeps the version mcpsafe asked for.
    t = await list(undefined);
    assert.equal(t.warning, undefined);
  } finally {
    srv.closeAllConnections?.();
    await new Promise((r) => srv.close(r));
  }
});
