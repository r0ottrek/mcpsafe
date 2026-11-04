// Round 2 regression tests for src/secrets.js: MCS001 false positives
// (paths, hosts, ARNs, scope lists, README placeholders, env var names, local
// dev databases), misses (nested ${...} defaults, lowercase keys) and
// linear-time matching.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { detectSecret, expandRefs, findSecrets, isPlaceholder } from '../src/secrets.js';
import { tmpdir, writeJson, FAKE } from './helpers.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'mcpsafe.js');
const scanJson = (dir) => {
  const r = spawnSync(process.execPath, [bin, '--no-home', '--home', tmpdir(), dir, '--json'], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
  return JSON.parse(r.stdout);
};

// Built at runtime, never committed as literals.
const PW = ['Xk29', 'vLq7', 'Rt'].join('');
const SLACK = ['xoxb', '1234567890', '1234567890123', 'AbCdEfGhIjKlMnOpQrStUvWx'].join('-');

// ---- i=1: settings that only look like secrets ----

test('backslash relative paths, upper-case hosts, ARNs, scope lists and enum values are settings', () => {
  const cases = [
    ['SSH_PRIVATE_KEY', 'keys\\id_ed25519'],
    ['GOOGLE_APPLICATION_CREDENTIALS', 'keys\\gcp\\sa_reader'],
    ['GOOGLE_APPLICATION_CREDENTIALS', 'credentials\\service-account'],
    ['GOOGLE_APPLICATION_CREDENTIALS', 'secrets/GCP/SA-Reader2'],
    ['AUTH_SERVER', 'Login.MicrosoftOnline.com'],
    ['AUTH_TOKEN', 'Login.MicrosoftOnline.com'],
    ['DB_SECRET_ARN', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/mcp/db-AbCdEf'],
    ['SECRET', 'arn:aws:secretsmanager:us-west-2:123456789012:secret:my-db-secret-AbCdEf'],
    ['AUTH_PERMISSIONS', 'Mail.Read,User.Read,Files.ReadWrite'],
    ['AUTH_TOKEN_SCOPE_LIST', 'Mail.Read,User.ReadBasic.All'],
    ['CREDENTIAL_SOURCE', 'EnvironmentCredential'],
    ['AZURE_CREDENTIAL', 'ManagedIdentityCredential'],
  ];
  for (const [k, v] of cases) assert.equal(detectSecret(v, k), null, `${k}=${v}`);
});

test('lowercase and dotted literal keys are still found', () => {
  assert.equal(detectSecret(['abcd1234', 'efgh5678', 'ijkl9012'].join('-'), 'API_KEY')?.confidence, 'medium');
  assert.equal(detectSecret(['prod', 'k9x2m7q4z8w1', 'abc'].join('.'), 'API_TOKEN')?.confidence, 'medium');
  assert.equal(detectSecret(['key', '3ax6xnjp29jd6fds4gc373sgvjxteol0'].join('-'), 'MAILGUN_API_KEY')?.confidence, 'medium');
  // Random mixed case that happens to read like camelCase is still a key.
  assert.equal(detectSecret(['yzuEpih1', 'Kowqa8OdHpr', 'CxgbZmeocCyir'].join(''), 'API_KEY')?.confidence, 'medium');
  assert.equal(detectSecret(FAKE.generic, 'CLIENT_SECRET')?.confidence, 'medium');
  // Password keys keep passphrases, which look like word lists.
  assert.equal(detectSecret(['correct', 'horse', 'battery', 'staple'].join('-'), 'DB_PASSWORD')?.confidence, 'medium');
});

// ---- hunt: secret manager references ----

test('ARNs and secret manager names point at a secret and are not one', () => {
  const arn = 'arn:aws:secretsmanager:us-west-2:123456789012:secret:my-db-secret-AbCdEf';
  for (const k of ['secret_arn', 'AWS_SECRET_ARN', 'DB_SECRET_ARN', 'API_KEY']) assert.equal(detectSecret(arn, k), null, k);
  assert.equal(detectSecret('projects/my-proj-123/secrets/github-token/versions/latest', 'SECRET_REF'), null);
  assert.equal(detectSecret('projects/my-proj-123/secrets/github-token/versions/latest', 'API_KEY'), null);
  assert.equal(detectSecret('@Microsoft.KeyVault(SecretUri=https://v.vault.azure.net/secrets/s/)', 'API_KEY'), null);
});

// ---- hunt: README placeholders with a vendor prefix ----

test('vendor-prefixed README placeholders are not secrets', () => {
  const cases = [
    ['SLACK_BOT_TOKEN', 'xoxb-your-bot-token'],
    ['SLACK_USER_TOKEN', 'xoxp-your-user-token'],
    ['SLACK_BOT_TOKEN', 'xoxb-your-slack-bot-token-here'],
    ['FIRECRAWL_API_KEY', 'fc-YOUR_API_KEY'],
    ['TAVILY_API_KEY', 'tvly-YOUR_API_KEY'],
    ['PERPLEXITY_API_KEY', 'pplx-YOUR_API_KEY'],
    ['OPENAI_API_KEY', 'sk-proj-YOUR_KEY'],
    ['OPENAI_API_KEY', ['sk', 'proj', 'REPLACE_WITH_YOUR_OPENAI_API_KEY_123'].join('-')],
    ['GITHUB_TOKEN', 'ghp_YOUR_TOKEN'],
    ['GITHUB_TOKEN', `ghp_${'YourGitHubPersonalAccessTokenGoesHere1'}`],
    ['GITHUB_TOKEN', `ghp_${'x'.repeat(36)}`],
    ['GITHUB_TOKEN', 'github_pat_YOUR_TOKEN'],
    ['STRIPE_KEY', 'sk_test_YOUR_KEY'],
    ['LINEAR_API_KEY', 'lin_api_YOUR_KEY'],
    ['HF_TOKEN', 'hf_YOUR_TOKEN'],
    ['ANTHROPIC_API_KEY', 'sk-ant-api03-...'],
    ['SLACK_BOT_TOKEN', 'xoxb-<token>'],
    ['API_KEY', 'token_here'],
  ];
  for (const [k, v] of cases) assert.equal(detectSecret(v, k), null, `${k}=${v}`);
  // Real tokens with the same prefixes are still found.
  assert.equal(detectSecret(SLACK, 'SLACK_BOT_TOKEN')?.type, 'Slack token');
  assert.equal(detectSecret(FAKE.github, 'GITHUB_TOKEN')?.type, 'GitHub token');
  assert.equal(detectSecret(FAKE.anthropic, 'ANTHROPIC_API_KEY')?.type, 'Anthropic API key');
});

test('a real token next to template text in a command line is still found', () => {
  const cmd = `curl -H 'x-api-key: ${FAKE.anthropic}' https://api.example.com/your/path`;
  assert.equal(detectSecret(cmd)?.type, 'Anthropic API key');
  assert.equal(detectSecret('curl -H "Authorization: Bearer xoxb-your-bot-token" https://slack.com/api'), null);
});

// ---- hunt: templates and env var names ----

test('mustache templates, env var names and $env: references are not secrets', () => {
  const cases = [
    ['GITHUB_TOKEN', '{{GITHUB_TOKEN}}'],
    ['GITHUB_TOKEN', '{{ github_token }}'],
    ['token-env-var', 'GITHUB_PERSONAL_ACCESS_TOKEN'],
    ['SECRET_KEY_ENV', 'DJANGO_SECRET_KEY'],
    ['API_KEY', 'OPENAI_API_KEY'],
    ['API_KEY', '$env:OPENAI_API_KEY'],
    ['API_KEY', 'env:OPENAI_API_KEY'],
    ['API_KEY', '%OPENAI_API_KEY%'],
  ];
  for (const [k, v] of cases) assert.equal(detectSecret(v, k), null, `${k}=${v}`);
  assert.ok(isPlaceholder('{{GITHUB_TOKEN}}'));
  assert.ok(isPlaceholder('$env:GITHUB_TOKEN'));
});

// ---- hunt: local dev databases ----

test('loopback database URLs with a well-known default password are not reported', () => {
  for (const v of [
    'postgresql://postgres:postgres@127.0.0.1:54322/postgres',
    'mysql://root:root@localhost:3306/test',
    'redis://default:redispw@localhost:6379',
    'postgresql://postgres:password@host.docker.internal:5432/db',
    'postgresql://postgres:postgres@[::1]:5432/db',
    'amqp://guest:guest@localhost:5672',
  ]) assert.equal(detectSecret(v), null, v);
  // A real password on loopback, or a default password on another host, still is.
  assert.equal(detectSecret(`postgresql://postgres:${PW}@127.0.0.1:5432/postgres`)?.type, 'Database URL with password');
  assert.equal(detectSecret('postgresql://postgres:postgres@db.prod.internal:5432/postgres')?.type, 'Database URL with password');
  assert.equal(detectSecret('postgresql://postgres:postgres@${DB_HOST}:5432/postgres')?.type, 'Database URL with password');
});

// ---- i=10: every form of ${...} default ----

test('literals in nested and shell-style ${...} defaults are found', () => {
  const t = FAKE.github;
  for (const v of [
    `\${GITHUB_TOKEN:-\${GH_TOKEN:-${t}}}`,
    `\${A:-\${B}${t}}`,
    `\${GITHUB_TOKEN:=${t}}`,
    `\${GITHUB_TOKEN=${t}}`,
    `\${GITHUB_TOKEN:?${t}}`,
    `\${GITHUB_TOKEN:+${t}}`,
    `\${GITHUB_TOKEN:-${t}`, // unclosed: literal text
  ]) assert.equal(detectSecret(v, 'GITHUB_PERSONAL_ACCESS_TOKEN')?.type, 'GitHub token', v);
  assert.equal(detectSecret(`\${A:-\${B:-${FAKE.generic}}}`, 'API_KEY')?.secret, FAKE.generic);
  assert.equal(expandRefs('${A:-${B:-x}}/${C}/${env:D}/${input:e}'), 'x///');
  for (const v of ['${A:-${B}}', '${input:x}', '${env:X}', '${A:-${B:-}}', '${workspaceFolder}']) assert.ok(isPlaceholder(v), v);
});

// ---- end to end ----

test('a project with only references and placeholders has no MCS001, a real token still does', () => {
  const dir = tmpdir();
  writeJson(path.join(dir, '.mcp.json'), {
    mcpServers: {
      aurora: { command: 'uvx', args: ['awslabs.postgres-mcp-server@1.0.9', '--secret_arn', 'arn:aws:secretsmanager:us-west-2:123456789012:secret:my-db-secret-AbCdEf'] },
      slack: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-slack@2025.4.25'], env: { SLACK_BOT_TOKEN: 'xoxb-your-bot-token' } },
      firecrawl: { command: 'npx', args: ['-y', 'firecrawl-mcp@1.0.0'], env: { FIRECRAWL_API_KEY: 'fc-YOUR_API_KEY' } },
      local: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2', 'postgresql://postgres:postgres@127.0.0.1:54322/postgres'] },
      tmpl: { command: 'npx', args: ['-y', 'gh-mcp@1.0.0', '--token-env-var', 'GITHUB_PERSONAL_ACCESS_TOKEN'], env: { GITHUB_TOKEN: '{{GITHUB_TOKEN}}' } },
    },
  });
  assert.deepEqual(scanJson(dir).findings.filter((f) => f.id === 'MCS001'), []);

  const real = tmpdir();
  writeJson(path.join(real, '.mcp.json'), { mcpServers: { gh: { command: 'npx', args: ['-y', 'gh-mcp@1.0.0'], env: { GITHUB_TOKEN: `\${GH:-\${GITHUB:-${FAKE.github}}}` } } } });
  const f = scanJson(real).findings.filter((x) => x.id === 'MCS001');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'critical');
  assert.ok(!JSON.stringify(f).includes(FAKE.github));
});

// ---- code review: linear time on hostile input ----

test('secret detection stays linear on 200KB adversarial values', () => {
  const N = 200_000;
  const fill = (unit) => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  const inputs = [
    '${', '${a:-', '${a:-${', '${a}', '}${', '{{', '<a', '$env:', 'mysql://a:', 'postgres://', 'xoxb-', 'sk-', 'sk-ant-',
    'a.', 'A.', 'a/', 'a\\', 'a,', 'a:', 'aB', 'Ab', 'a-', 'a_', 'A_', '@a', 'a@', '-----BEGIN ', 'x', 'here ', 'arn:aws:',
  ].map(fill);
  inputs.push(`mysql://${'a'.repeat(N)}`, `a@${'a.'.repeat(N / 2)}`, `${'a.'.repeat(N / 2)} `, `Bearer ${'a'.repeat(N)} x`);
  for (const v of inputs) {
    for (const key of ['', 'API_KEY', 'DB_PASSWORD']) {
      const t0 = performance.now();
      findSecrets(v, key);
      isPlaceholder(v);
      const ms = performance.now() - t0;
      assert.ok(ms < 200, `${JSON.stringify(v.slice(0, 12))} with key "${key}" took ${ms.toFixed(0)} ms`);
    }
  }
});
