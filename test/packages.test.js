import { test } from 'node:test';
import assert from 'node:assert/strict';
import { launchedPackages, effectiveCommand, dockerImageRef } from '../src/packages.js';
import { server } from './helpers.js';

const pkg = (command, args) => launchedPackages(server({ command, args }))[0];

test('npx: unpinned, pinned, @latest, scoped', () => {
  assert.equal(pkg('npx', ['-y', '@modelcontextprotocol/server-github']).pinned, false);
  assert.equal(pkg('npx', ['-y', '@playwright/mcp@0.0.84']).pinned, true);
  assert.equal(pkg('npx', ['@playwright/mcp@latest']).pinned, false);
  assert.equal(pkg('npx', ['-y', '@playwright/mcp@^0.0.84']).pinned, false);
  assert.equal(pkg('npx', ['-y', '@playwright/mcp@0.0.84']).name, '@playwright/mcp');
  assert.equal(pkg('npx', ['-y', 'firecrawl-mcp@3.1.0']).name, 'firecrawl-mcp');
});

test('npx: --package flag and npm exec / pnpm dlx / bunx', () => {
  assert.equal(pkg('npx', ['--package', 'foo@1.2.3', 'foo-bin']).spec, 'foo@1.2.3');
  assert.equal(pkg('npx', ['--package=foo', 'foo-bin']).pinned, false);
  assert.equal(pkg('npm', ['exec', 'foo@1.0.0']).pinned, true);
  assert.equal(pkg('pnpm', ['dlx', 'foo']).name, 'foo');
  assert.equal(pkg('bunx', ['foo@2.0.0']).pinned, true);
  assert.equal(pkg('node', ['server.js']), undefined);
});

test('npx: git and local specs', () => {
  assert.equal(pkg('npx', ['github:user/repo']).kind, 'git');
  assert.equal(pkg('npx', ['user/repo']).kind, 'git');
  assert.equal(pkg('npx', [`github:user/repo#${'a'.repeat(40)}`]).pinned, true);
  assert.equal(pkg('npx', ['./local-server']).kind, 'local');
});

test('uvx / uv tool run / pipx', () => {
  assert.equal(pkg('uvx', ['mcp-server-fetch']).pinned, false);
  assert.equal(pkg('uvx', ['mcp-server-fetch==2026.10.28']).pinned, true);
  assert.equal(pkg('uvx', ['mcp-server-fetch@2026.10.28']).pinned, true);
  assert.equal(pkg('uvx', ['mcp-server-fetch>=1.0']).pinned, false);
  assert.equal(pkg('uvx', ['--from', 'git+https://github.com/a/b', 'b']).kind, 'git');
  assert.equal(pkg('uv', ['tool', 'run', 'serena==0.1.4']).pinned, true);
  assert.equal(pkg('pipx', ['run', 'mcp-server-git']).pinned, false);
  assert.equal(pkg('uvx', ['--python', '3.12', 'mcp-server-time']).name, 'mcp-server-time');
});

test('docker images', () => {
  assert.equal(dockerImageRef('mcp/fetch').pinned, false);
  assert.equal(dockerImageRef('mcp/fetch:latest').pinned, false);
  assert.equal(dockerImageRef('mcp/fetch:1.2').pinned, true);
  assert.equal(dockerImageRef('localhost:5000/img').pinned, false);
  assert.equal(dockerImageRef(`mcp/fetch@sha256:${'b'.repeat(64)}`).digest, true);
  assert.equal(pkg('docker', ['run', '-i', '--rm', '-e', 'TOKEN', 'ghcr.io/github/github-mcp-server']).name, 'ghcr.io/github/github-mcp-server');
});

test('unwraps cmd /c and whole command lines', () => {
  assert.equal(effectiveCommand(server({ command: 'cmd', args: ['/c', 'npx', '-y', 'foo'] })).base, 'npx');
  assert.equal(pkg('cmd', ['/c', 'npx', '-y', 'foo']).name, 'foo');
  assert.equal(pkg('npx -y foo@1.0.0', []).pinned, true);
  assert.equal(effectiveCommand(server({ command: 'C:\\Program Files\\nodejs\\npx.cmd', args: ['foo'] })).base, 'npx');
});
