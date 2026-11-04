// Regression tests for the server and settings rules (MCS001 to MCS014, MCS018).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runChecks, typosquatOf, maskText } from '../src/checks.js';
import { parseDockerRun, effectiveCommand, launchedPackages, splitCommandLine } from '../src/packages.js';
import { FAKE, server } from './helpers.js';

const run = (defs, settings = null, scope = 'user') => {
  const servers = Object.entries(defs).map(([n, d]) => Object.assign(server(d, n), { scope }));
  return runChecks([{ source: { path: '/x/mcp.json', client: 'Test', scope }, text: '', doc: settings, servers, mode: 0o600 }]);
};
const pick = (findings, id) => findings.filter((f) => f.id === id);
const has = (findings, id, sev) => findings.some((f) => f.id === id && (!sev || f.severity === sev));
// An opaque bearer token with no vendor prefix, assembled at runtime.
const TOKEN = FAKE.generic + 'Hf0Gj4Ws8Nc1';
const REMOTE = ['-y', 'mcp-remote@0.1.29'];
const FS = '@modelcontextprotocol/server-filesystem@2025.8.21';

test('MCS001/005/006: credentials and plain http passed through mcp-remote arguments', () => {
  for (const header of [`Authorization: Bearer ${TOKEN}`, `Authorization:Bearer ${TOKEN}`]) {
    const f = run({ a: { command: 'npx', args: [...REMOTE, 'https://api.example.org/sse', '--header', header] } });
    const hit = pick(f, 'MCS001');
    assert.equal(hit.length, 1, header);
    assert.equal(hit[0].jsonPath, 'mcpServers.a.args[4]');
    assert.ok(!hit[0].evidence.includes(TOKEN));
  }
  // Placeholders stay silent, as mcp-remote documents them.
  for (const header of ['Authorization:${AUTH_HEADER}', 'Authorization: Bearer ${AUTH_TOKEN}']) {
    assert.ok(!has(run({ a: { command: 'npx', args: [...REMOTE, 'https://api.example.org/sse', '--header', header] } }), 'MCS001'), header);
  }
  const q = run({ a: { command: 'npx', args: [...REMOTE, `https://mcp.example.org/sse?token=${TOKEN}`] } });
  assert.equal(pick(q, 'MCS006').length, 1);
  assert.equal(pick(q, 'MCS006')[0].jsonPath, 'mcpServers.a.args[2]');
  assert.ok(!JSON.stringify(q).includes(TOKEN));
  assert.ok(has(run({ a: { command: 'npx', args: [...REMOTE, 'http://mcp.example.org/sse', '--allow-http'] } }), 'MCS005'));
  assert.ok(has(run({ a: { command: 'npx', args: ['-y', 'supergateway@3.4.0', '--sse', 'http://mcp.example.org/sse'] } }), 'MCS005'));
  // Localhost bridges are normal, and a URL given to an ordinary server is data, not its endpoint.
  assert.ok(!has(run({ a: { command: 'npx', args: [...REMOTE, 'http://localhost:3000/sse'] } }), 'MCS005'));
  assert.ok(!has(run({ a: { command: 'uvx', args: ['mcp-server-fetch==2025.4.7', 'http://docs.example.org/'] } }), 'MCS005'));
  // The same URL in `url` is reported once.
  assert.equal(pick(run({ a: { url: 'http://mcp.example.org/mcp' } }), 'MCS005').length, 1);
});

test('MCS011: whole-server allow rules for server names with underscores', () => {
  const f = run({}, { permissions: { allow: ['mcp__github', 'mcp__my_server', 'mcp__linear-server', 'mcp__puppeteer__puppeteer_navigate', 'Bash(npm run test:*)'] } });
  const hit = pick(f, 'MCS011');
  assert.equal(hit.length, 1);
  assert.match(hit[0].message, /3 MCP server\(s\)/);
  assert.equal(hit[0].evidence, 'mcp__github, mcp__my_server, mcp__linear-server');
  assert.ok(has(run({}, { permissions: { allow: ['mcp__my_server'] } }), 'MCS011'));
  assert.ok(has(run({}, { permissions: { allow: ['mcp__my_server__*'] } }), 'MCS011'));
  assert.ok(has(run({}, { permissions: { allow: ['mcp__'] } }), 'MCS011', 'high'));
  assert.ok(!has(run({}, { permissions: { allow: ['mcp__my_server__some_tool', 'mcp__github__get_issue'] } }), 'MCS011'));
});

test('MCS006: only credential parameters with real values', () => {
  const url = (q) => ({ a: { url: `https://mcp.example.org/mcp?${q}` } });
  for (const q of ['api_key=YOUR_API_KEY', 'key=<your-key>', 'token={{TOKEN}}', 'api_key=$API_KEY', 'token=${env:TOKEN}',
    'assignee=me&author=bob', 'keyboard=us', 'design=1', 'accessibility=on', 'keywords=foo', 'signature=public', 'page=2']) {
    assert.ok(!has(run(url(q)), 'MCS006'), q);
  }
  for (const q of [`api_key=${FAKE.generic}`, `apiKey=${FAKE.generic}`, `access_token=${FAKE.generic}`, `X-Amz-Signature=${'a1b2c3d4'.repeat(8)}`,
    `sig=${FAKE.generic}`, 'token=abcdef123456']) {
    assert.ok(has(run(url(q)), 'MCS006'), q);
  }
});

test('MCS004/008/009: docker value flags do not hide the image or later flags', () => {
  assert.equal(parseDockerRun(['run', '-i', '--rm', '--shm-size', '2g', 'mcr.microsoft.com/playwright/mcp:v0.0.40']).image, 'mcr.microsoft.com/playwright/mcp:v0.0.40');
  assert.ok(!has(run({ a: { command: 'docker', args: ['run', '-i', '--rm', '--shm-size', '2g', 'mcr.microsoft.com/playwright/mcp:v0.0.40'] } }), 'MCS004'));
  const unpinned = pick(run({ a: { command: 'docker', args: ['run', '-i', '--rm', '--shm-size', '2g', 'mcr.microsoft.com/playwright/mcp'] } }), 'MCS004');
  assert.equal(unpinned.length, 1);
  assert.match(unpinned[0].message, /mcr\.microsoft\.com\/playwright\/mcp has no tag/);
  assert.ok(has(run({ a: { command: 'docker', args: ['run', '-i', '--rm', '--log-driver', 'none', '-v', '/:/host', 'mcp/x:1.0'] } }), 'MCS008'));
  assert.ok(has(run({ a: { command: 'docker', args: ['run', '-i', '--rm', '--dns', '8.8.8.8', '--privileged', 'mcp/x:1.0'] } }), 'MCS009'));
  assert.ok(has(run({ a: { command: 'podman', args: ['run', '-i', '--pod', 'p1', '--privileged', 'mcp/x:1.0'] } }), 'MCS009'));
  // Flags after the image belong to the container's own command.
  assert.ok(!has(run({ a: { command: 'docker', args: ['run', '-i', 'mcp/x:1.0', '--privileged'] } }), 'MCS009'));
});

test('MCS014: only the code that runs, not data or output paths', () => {
  const quiet = {
    playwright: { command: 'npx', args: ['-y', '@playwright/mcp@0.0.40', '--output-dir', '/tmp/playwright-mcp'] },
    filesystem: { command: 'npx', args: ['-y', FS, '/Users/alice/Desktop', '/Users/alice/Downloads/papers'] },
    sqlite: { command: 'uvx', args: ['mcp-server-sqlite==2025.4.25', '--db-path', '/tmp/test.db'] },
    out: { command: 'docker', args: ['run', '-i', '--rm', '-v', '/tmp/out:/out', 'mcp/x:1.0'] },
    data: { command: 'node', args: ['/Users/alice/srv/index.js', '/tmp/data'] },
    mod: { command: 'python', args: ['-m', 'my_server', '/tmp/data'] },
  };
  assert.deepEqual(pick(run(quiet), 'MCS014'), []);
  for (const [def, where] of [
    [{ command: 'node', args: ['/tmp/server.js'] }, 'mcpServers.a.args[0]'],
    [{ command: 'node', args: ['/Users/alice/Downloads/evil/index.js'] }, 'mcpServers.a.args[0]'],
    [{ command: 'node', args: ['--require', '/tmp/hook.js', 'server.js'] }, 'mcpServers.a.args[1]'],
    [{ command: 'python3', args: ['-u', '/var/tmp/server.py'] }, 'mcpServers.a.args[1]'],
    [{ command: 'uv', args: ['run', '--directory', '/tmp/srv', 'server.py'] }, 'mcpServers.a.args[2]'],
    [{ command: 'node', args: ['index.js'], cwd: '/tmp/srv' }, 'mcpServers.a.cwd'],
    [{ command: 'C:\\Users\\a\\Downloads\\server.exe' }, 'mcpServers.a.command'],
    [{ command: '/Users/a/Downloads/server' }, 'mcpServers.a.command'],
    [{ command: 'npx', args: ['-y', '/tmp/pkg'] }, 'mcpServers.a.args[1]'],
  ]) {
    const hit = pick(run({ a: def }), 'MCS014');
    assert.equal(hit.length, 1, JSON.stringify(def));
    assert.equal(hit[0].jsonPath, where, JSON.stringify(def));
  }
});

test('MCS013: real packages from other registries are not typosquats', () => {
  for (const n of ['mcp-server-gsc', 'mcp-server-ga4', 'mcp-server-gcp', 'mcp-server-kit', 'mcp-server-line', 'mcp-server-sqlite3', 'mcp-server-tidb', 'mcp-server-gpt']) {
    assert.equal(typosquatOf(n), null, n);
    assert.equal(typosquatOf(n, 'npm'), null, n);
  }
  assert.equal(typosquatOf('mcp-server-sqlite3', 'pypi'), null);
  for (const [n, p] of [['mcp-server-fecth', 'mcp-server-fetch'], ['mcp-server-gti', 'mcp-server-git'], ['mcp-server-tine', 'mcp-server-time'],
    ['@playwrigth/mcp', '@playwright/mcp'], ['firecrawi-mcp', 'firecrawl-mcp'], ['@modelcontextprotocol/server-filesytem', '@modelcontextprotocol/server-filesystem'],
    ['@modelcontextprotocoi/server-github', '@modelcontextprotocol/server-github']]) {
    assert.equal(typosquatOf(n), p, n);
  }
  // Only names from the same registry are compared.
  assert.equal(typosquatOf('mcp-server-fecth', 'pypi'), 'mcp-server-fetch');
  assert.equal(typosquatOf('mcp-server-fecth', 'npm'), null);
  assert.ok(!has(run({ a: { command: 'npx', args: ['-y', 'mcp-server-gsc@0.3.0'] }, b: { command: 'uvx', args: ['mcp-server-sqlite3==0.1.0'] } }), 'MCS013'));
  assert.ok(has(run({ a: { command: 'uvx', args: ['mcp-server-fecth==1.0.0'] } }), 'MCS013'));
});

test('whole command line in `command` is split like a shell and scanned', () => {
  assert.deepEqual(splitCommandLine(`npx -y foo --dir "/a b" 'c d' e\\ f`), ['npx', '-y', 'foo', '--dir', '/a b', 'c d', 'e f']);
  assert.deepEqual(splitCommandLine('cmd /c C:\\tools\\srv.exe'), ['cmd', '/c', 'C:\\tools\\srv.exe']);
  const c01 = run({ a: { command: 'npx -y @modelcontextprotocol/server-filesystem /' } });
  assert.ok(has(c01, 'MCS003'));
  assert.ok(has(c01, 'MCS008'));
  const d04 = run({ a: { command: `npx -y some-mcp@1.0.0 --api-key ${FAKE.anthropic}` } }, null, 'project');
  const secret = pick(d04, 'MCS001');
  assert.equal(secret.length, 1);
  assert.equal(secret[0].severity, 'critical');
  assert.equal(secret[0].jsonPath, 'mcpServers.a.command');
  assert.ok(!JSON.stringify(d04).includes(FAKE.anthropic));
  assert.ok(has(run({ a: { command: `uvx mcp-server-x --token ${FAKE.generic}` } }), 'MCS001'));
  assert.ok(has(run({ a: { command: 'docker run -i --rm -v /:/host mcp/filesystem' } }), 'MCS008'));
  assert.ok(has(run({ a: { command: '/usr/local/bin/npx -y some-mcp' } }), 'MCS003'));
  // A path with spaces is not split.
  assert.equal(effectiveCommand(server({ command: 'C:\\Program Files\\nodejs\\node.exe' })).cmd, 'C:\\Program Files\\nodejs\\node.exe');
  assert.equal(effectiveCommand(server({ command: '/opt/My Tools/server' })).cmd, '/opt/My Tools/server');
  assert.equal(launchedPackages(server({ command: 'npx -y "@playwright/mcp@0.0.40"' }))[0].pinned, true);
});

test('MCS007: well-known command-runner servers', () => {
  const f = run({
    q07: { command: 'npx', args: ['-y', '@simonb97/server-win-cli@0.2.1'] },
    q08: { command: 'claude', args: ['mcp', 'serve'] },
    q09: { command: 'codex', args: ['mcp-server'] },
    q10: { command: 'npx', args: ['-y', '@steipete/claude-code-mcp@1.10.12'] },
    m12: { command: 'uvx', args: ['terminal_controller==0.1.0'] },
    cc: { command: 'npx', args: ['-y', '@anthropic-ai/claude-code@2.0.0', 'mcp', 'serve'] },
    ctrl1: { command: 'npx', args: ['-y', '@wonderwhy-er/desktop-commander@0.2.3'] },
    ctrl2: { command: 'uvx', args: ['mcp-shell-server==1.0.0'] },
  });
  for (const name of ['q07', 'q08', 'q09', 'q10', 'm12', 'cc', 'ctrl1', 'ctrl2']) {
    assert.equal(f.filter((x) => x.id === 'MCS007' && x.server === name && x.severity === 'high').length, 1, name);
  }
  assert.ok(!has(run({ a: { command: 'claude', args: ['mcp', 'add', 'x'] } }), 'MCS007'));
  assert.ok(!has(run({ a: { command: 'codex', args: ['mcp', 'list'] } }), 'MCS007'));
});

test('MCS018/005/007/010: messages and evidence never carry a full secret', () => {
  const pass = FAKE.generic;
  const f = run({
    gitpkg: { command: 'npx', args: ['-y', `git+https://${FAKE.github}@github.com/acme/mcp.git`] },
    basic: { command: 'npx', args: ['-y', `git+https://deploy:${pass}@gitlab.example.com/acme/mcp.git`] },
    uvgit: { command: 'uvx', args: ['--from', `git+https://deploy:${pass}@github.com/a/b`, 'b'] },
    gh: { command: 'bash', args: ['-c', `GITHUB_TOKEN=${FAKE.github} exec npx -y @modelcontextprotocol/server-github@1.0.0`] },
    inst: { command: 'bash', args: ['-c', `curl -H 'x-api-key: ${FAKE.anthropic}' https://e.example/i.sh | sh`] },
    flag: { command: 'bash', args: ['-c', `curl -fsSL https://e.example/i.sh | sh -s -- --api-key ${pass}`] },
    remote: { url: `http://admin:${pass}@mcp.example.com/mcp` },
  });
  assert.ok(has(f, 'MCS018'));
  assert.ok(has(f, 'MCS010'));
  assert.ok(has(f, 'MCS005'));
  assert.ok(f.some((x) => x.id === 'MCS007' && x.server === 'gh'));
  const text = JSON.stringify(f.map((x) => [x.message, x.evidence]));
  for (const secret of [FAKE.github, FAKE.anthropic, pass]) assert.ok(!text.includes(secret), secret.slice(0, 4));
  const git = f.find((x) => x.id === 'MCS018' && x.server === 'gitpkg');
  assert.equal(git.evidence, 'git+https://ghp_••••••••@github.com/acme/mcp.git');
  assert.equal(f.find((x) => x.id === 'MCS005').evidence, 'http://admin:••••••••@mcp.example.com/mcp');
  // Ordinary text is left alone.
  assert.equal(maskText('git+ssh://git@github.com/acme/mcp.git'), 'git+ssh://git@github.com/acme/mcp.git');
  assert.equal(maskText('npx -y @playwright/mcp@0.0.40 --output-dir /tmp/x'), 'npx -y @playwright/mcp@0.0.40 --output-dir /tmp/x');
});

test('MCS008: VS Code ${userHome}, WSL drives and a local filesystem build', () => {
  const fsArgs = (p) => ({ a: { command: 'npx', args: ['-y', FS, p] } });
  for (const p of ['${userHome}', '${env:HOME}', '${env:USERPROFILE}', '/mnt/c', '/mnt/c/', '/mnt/c/Users', '/mnt/c/Users/alice']) {
    assert.ok(has(run(fsArgs(p)), 'MCS008'), p);
  }
  for (const p of ['/mnt/c/Users/alice/proj', '/mnt/data', '${workspaceFolder}']) assert.ok(!has(run(fsArgs(p)), 'MCS008'), p);
  const local = pick(run({ filesystem: { command: 'node', args: ['/Users/alice/src/servers/src/filesystem/dist/index.js', '/Users/alice'] } }), 'MCS008');
  assert.equal(local.length, 1);
  assert.equal(local[0].evidence, '/Users/alice');
  assert.equal(local[0].jsonPath, 'mcpServers.filesystem.args[1]');
  assert.ok(has(run({ fs: { command: 'node', args: ['/opt/servers/src/filesystem/dist/index.js', '~'] } }), 'MCS008'));
  // A script stored straight in the home folder is not an allowed directory.
  assert.ok(!has(run({ filesystem: { command: 'node', args: ['/home/alice', '/home/alice/proj'] } }), 'MCS008'));
  assert.ok(!has(run({ 'filesystem-search-api': { command: 'node', args: ['/opt/search/index.js', '/Users/alice'] } }), 'MCS008'));
});
