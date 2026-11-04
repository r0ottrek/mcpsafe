import fs from 'node:fs';
import path from 'node:path';
import { discover } from './discover.js';
import { loadConfig } from './parse.js';
import { runChecks, checkTools } from './checks.js';
import { listTools } from './live.js';
import { score, sortFindings } from './score.js';
import { SEVERITIES } from './rules.js';
import { parseJsonc } from './jsonc.js';
import { lineOf } from './locate.js';

export const VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

// Accepts { server: [tools] }, { server: { tools } } or a raw tools/list result { tools }.
export function readToolsFile(file) {
  const doc = parseJsonc(fs.readFileSync(file, 'utf8'));
  if (Array.isArray(doc?.tools)) return [{ server: path.basename(file, '.json'), tools: doc.tools, file }];
  return Object.entries(doc).map(([server, v]) => ({ server, tools: Array.isArray(v) ? v : v?.tools || [], file }));
}

/**
 * @param {object} o
 * @param {string[]} [o.paths]
 * @param {string} [o.home]
 * @param {boolean} [o.includeHome]
 * @param {boolean} [o.connect]
 * @param {string[]} [o.toolsFiles]
 * @param {string[]} [o.ignore]
 * @param {(msg: string) => void} [o.onProgress]
 */
export async function scan(o = {}) {
  const sources = discover({ paths: o.paths, home: o.home, includeHome: o.includeHome !== false, depth: o.depth });
  const configs = sources.map(loadConfig);
  let findings = runChecks(configs);
  const allServers = configs.flatMap((c) => c.servers);

  const toolSets = [];
  const liveErrors = [];
  for (const f of o.toolsFiles || []) toolSets.push(...readToolsFile(f));
  if (o.connect) {
    for (const s of allServers.filter((x) => !x.disabled)) {
      o.onProgress?.(`Listing tools from "${s.name}"…`);
      try {
        toolSets.push({ server: s.name, tools: await listTools(s), file: s.file });
      } catch (e) {
        liveErrors.push({ server: s.name, error: e.message });
      }
    }
  }
  const byName = Object.fromEntries(allServers.map((s) => [s.name, s]));
  findings.push(...checkTools(toolSets, byName));

  const ignore = new Set((o.ignore || []).map((x) => x.toUpperCase()));
  findings = sortFindings(findings.filter((f) => !ignore.has(f.id)));
  const textOf = Object.fromEntries(configs.map((c) => [c.source.path, c.text]));
  for (const f of findings) f.line = f.line ?? lineOf(textOf[f.file], f.jsonPath) ?? lineOf(textOf[f.file], f.serverPath);
  return {
    version: VERSION,
    generatedAt: new Date().toISOString(),
    live: !!o.connect,
    configs,
    servers: allServers.length,
    toolsScanned: toolSets.reduce((n, t) => n + t.tools.length, 0),
    liveErrors,
    findings,
    score: score(findings),
  };
}

export function atOrAbove(findings, sev) {
  const limit = SEVERITIES.indexOf(sev);
  return findings.filter((f) => SEVERITIES.indexOf(f.severity) <= limit);
}

// JSON-safe view (drops raw file text and raw server objects).
export function toJson(result) {
  return {
    tool: 'mcpsafe',
    version: result.version,
    generatedAt: result.generatedAt,
    score: result.score,
    files: result.configs.map((c) => ({ path: c.source.path, client: c.source.client, scope: c.source.scope, servers: c.servers.map((s) => s.name), error: c.error })),
    servers: result.servers,
    toolsScanned: result.toolsScanned,
    liveErrors: result.liveErrors,
    findings: result.findings,
  };
}
