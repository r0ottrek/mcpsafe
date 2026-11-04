import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir, writeJson, FAKE } from './helpers.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'mcpsafe.js');
const run = (args, opts = {}) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', cwd: opts.cwd || root, env: { ...process.env, NO_COLOR: '1' } });

test('discovers user configs from a fake home directory', () => {
  const home = tmpdir();
  writeJson(path.join(home, 'Library/Application Support/Claude/claude_desktop_config.json'), {
    mcpServers: { github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: FAKE.github } } },
  }, 0o644);
  writeJson(path.join(home, '.claude.json'), { projects: { '/work/app': { enableAllProjectMcpServers: true, mcpServers: { db: { command: 'uvx', args: ['mcp-server-sqlite'] } } } } });
  writeJson(path.join(home, '.cursor/mcp.json'), '{ // comment\n "mcpServers": { "remote": { "url": "http://mcp.remote.dev/sse", }, }, }');
  writeJson(path.join(home, '.config/Code/User/settings.json'), '{ "chat.tools.autoApprove": true, /* c */ "mcp": { "servers": { "t": { "command": "npx", "args": ["foo@1.0.0"] } } } }');
  writeJson(path.join(home, '.gemini/settings.json'), { mcpServers: { g: { httpUrl: 'https://x.dev/mcp', trust: true } } });

  const r = run(['--home', home, '--json'], { cwd: tmpdir() });
  const out = JSON.parse(r.stdout);
  assert.equal(out.files.length, 5);
  assert.equal(out.servers, 5);
  const ids = new Set(out.findings.map((f) => f.id));
  for (const id of ['MCS001', 'MCS002', 'MCS003', 'MCS005', 'MCS011', 'MCS012']) assert.ok(ids.has(id), id);
  assert.ok(!r.stdout.includes(FAKE.github), 'secret must be masked in output');
});

test('without paths only the current folder is scanned, not subfolders', () => {
  const home = tmpdir();
  const cwd = tmpdir();
  writeJson(path.join(cwd, '.mcp.json'), { mcpServers: { top: { command: 'node', args: ['a.js'] } } });
  writeJson(path.join(cwd, 'sub/project/.mcp.json'), { mcpServers: { nested: { command: 'node', args: ['b.js'] } } });
  const plain = JSON.parse(run(['--home', home, '--json'], { cwd }).stdout);
  assert.deepEqual(plain.files.flatMap((f) => f.servers), ['top']);
  const explicit = JSON.parse(run(['--no-home', cwd, '--json'], { cwd }).stdout);
  assert.deepEqual(explicit.files.flatMap((f) => f.servers).sort(), ['nested', 'top']);
});

test('exit codes: --fail-on and --min-score', () => {
  const risky = path.join(root, 'examples/risky-setup');
  const safe = path.join(root, 'examples/safe-setup');
  assert.equal(run(['--no-home', risky]).status, 0);
  assert.equal(run(['--no-home', risky, '--fail-on', 'high']).status, 1);
  assert.equal(run(['--no-home', safe, '--fail-on', 'low']).status, 0);
  assert.equal(run(['--no-home', safe, '--min-score', '90']).status, 0);
  assert.equal(run(['--no-home', risky, '--min-score', '50']).status, 1);
  assert.equal(run(['--fail-on', 'bogus']).status, 2);
});

test('--ignore removes rules', () => {
  const r = run(['--no-home', path.join(root, 'examples/risky-setup'), '--json', '--ignore', 'MCS003,MCS004']);
  const out = JSON.parse(r.stdout);
  assert.ok(!out.findings.some((f) => f.id === 'MCS003' || f.id === 'MCS004'));
});

test('writes HTML and SARIF reports', () => {
  const dir = tmpdir();
  const html = path.join(dir, 'r.html');
  const sarif = path.join(dir, 'r.sarif');
  const r = run(['--no-home', path.join(root, 'examples/risky-setup'), '--tools', path.join(root, 'examples/risky-setup/tools.json'), '--html', html, '--sarif', sarif]);
  assert.equal(r.status, 0);
  const page = fs.readFileSync(html, 'utf8');
  assert.match(page, /MCP configuration audit/);
  assert.match(page, /Hidden instructions in tool description/);
  assert.ok(!page.includes('<IMPORTANT>'), 'tool text must be escaped');
  const s = JSON.parse(fs.readFileSync(sarif, 'utf8'));
  assert.equal(s.version, '2.1.0');
  assert.ok(s.runs[0].results.length > 10);
  assert.ok(s.runs[0].results.every((x) => x.locations[0].physicalLocation.region.startLine >= 1));
  assert.ok(s.runs[0].results.some((x) => x.locations[0].physicalLocation.region.startLine > 1));
});

test('--connect lists tools from a live stdio server (with pagination)', () => {
  const dir = tmpdir();
  writeJson(path.join(dir, '.mcp.json'), { mcpServers: { calc: { command: process.execPath, args: [path.join(root, 'test/fixtures/poisoned-server.js')] } } });
  const r = run(['--no-home', dir, '--connect', '--json']);
  const out = JSON.parse(r.stdout);
  assert.equal(out.toolsScanned, 2);
  const poison = out.findings.find((f) => f.id === 'MCS016');
  assert.ok(poison && poison.severity === 'critical');
  assert.match(poison.message, /multiply/);
});

test('--connect reports servers that fail to start', () => {
  const dir = tmpdir();
  writeJson(path.join(dir, '.mcp.json'), { mcpServers: { broken: { command: 'this-command-does-not-exist-xyz' } } });
  const out = JSON.parse(run(['--no-home', dir, '--connect', '--json']).stdout);
  assert.equal(out.liveErrors.length, 1);
});

test('handles unparsable and empty files', () => {
  const dir = tmpdir();
  writeJson(path.join(dir, '.mcp.json'), '{ not json');
  writeJson(path.join(dir, '.cursor/mcp.json'), '');
  const r = run(['--no-home', dir, '--json']);
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.ok(out.files.some((f) => /parse/.test(f.error || '')));
});

test('--help, --version and --rules', () => {
  assert.match(execFileSync(process.execPath, [bin, '--help'], { encoding: 'utf8' }), /Usage/);
  assert.match(execFileSync(process.execPath, [bin, '--version'], { encoding: 'utf8' }), /^\d+\.\d+\.\d+/);
  assert.equal(execFileSync(process.execPath, [bin, '--rules'], { encoding: 'utf8' }).trim().split('\n').length, 18);
});
