import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Fake credentials are assembled at runtime so that no real-looking secret is
// committed to the repository.
export const FAKE = {
  github: `ghp_${'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7c'}`,
  anthropic: ['sk', 'ant', 'api03', 'Zq8Xw2Lm9Pk4Rt7Yu1Io3Pa6Sd'].join('-'),
  aws: ['AKIA', 'Q7RT2MZP4LK9WX3B'].join(''),
  generic: 'q7Vd93KfLx02PzR8mT4n',
};

export function tmpdir(prefix = 'mcpsafe-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function writeJson(file, data, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof data === 'string' ? data : JSON.stringify(data, null, 2));
  if (mode != null) fs.chmodSync(file, mode);
  return file;
}

export function server(def, name = 'srv') {
  return {
    name, client: 'Test', file: '/x/mcp.json', scope: 'user', jsonPath: `mcpServers.${name}`,
    transport: def.url ? 'http' : 'stdio', command: def.command ?? null, args: def.args ?? [], env: def.env ?? {},
    url: def.url ?? null, headers: def.headers ?? {}, cwd: def.cwd ?? null, disabled: !!def.disabled,
    autoApprove: def.autoApprove ?? [], trust: !!def.trust, raw: def,
  };
}
