import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectSecret, isPlaceholder, mask } from '../src/secrets.js';
import { FAKE } from './helpers.js';

test('detects known token formats', () => {
  assert.equal(detectSecret(FAKE.github).type, 'GitHub token');
  assert.equal(detectSecret(FAKE.anthropic).type, 'Anthropic API key');
  assert.equal(detectSecret(FAKE.aws).type, 'AWS access key ID');
  assert.equal(detectSecret('postgresql://admin:s3cretpass@db:5432/x').type, 'Database URL with password');
  assert.equal(detectSecret(`Bearer ${FAKE.generic}`).confidence, 'high');
});

test('generic credentials need a secret-looking key name', () => {
  assert.equal(detectSecret(FAKE.generic, 'WEATHER_API_KEY').confidence, 'medium');
  assert.equal(detectSecret(FAKE.generic, 'REGION'), null);
  assert.equal(detectSecret('aaaaaaaaaaaaaaaa', 'API_KEY'), null); // low entropy
});

test('ignores placeholders and references', () => {
  for (const v of ['${env:GITHUB_TOKEN}', '${input:token}', '$GITHUB_TOKEN', '%TOKEN%', '<your-token>', 'your_api_key_here', 'Bearer ${input:t}', 'true', '']) {
    assert.ok(isPlaceholder(v) || detectSecret(v, 'TOKEN') === null, v);
  }
  assert.equal(detectSecret('/Users/me/.config/token.txt', 'TOKEN_FILE'), null);
  assert.equal(detectSecret('https://api.example.com', 'AUTH_URL'), null);
});

test('masks secrets', () => {
  assert.ok(!mask(FAKE.github).includes(FAKE.github.slice(6)));
  assert.equal(mask('short'), '••••••••');
});
