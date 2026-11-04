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

// An error caused by the user's input (a bad path or file), as opposed to a
// bug. The CLI prints its message without a stack trace.
export class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
    this.expected = true;
  }
}

const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isTool = (t) => isObject(t) && typeof t.name === 'string';
const isEnvelope = (v) => isObject(v) && ('jsonrpc' in v || ('id' in v && ('result' in v || 'error' in v)));
// The tools array held by one entry: [tools], { tools } or a saved JSON-RPC
// response { result: { tools } }. Anything else gives null.
function toolsOf(v) {
  if (Array.isArray(v)) return v;
  if (!isObject(v)) return null;
  if (Array.isArray(v.tools)) return v.tools;
  if (isObject(v.result) && Array.isArray(v.result.tools)) return v.result.tools;
  return null;
}
const SHAPES = 'expected a tools/list result ({"tools": [...]}), a saved JSON-RPC response, a tools array, or {"server": [tools]}';

// Accepts a raw tools/list result { tools }, a saved JSON-RPC response
// { jsonrpc, id, result: { tools } } or a batch of them, a bare tools array,
// and per-server maps { server: [tools] } or { server: { tools } }. The
// single-server shapes are named after the file, so two saved responses stay
// separate servers.
export function readToolsFile(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    const why = e.code === 'ENOENT' ? 'no such file' : e.code === 'EISDIR' ? 'it is a folder' : e.code || e.message;
    throw new UsageError(`cannot read tools file ${file}: ${why}`);
  }
  let doc;
  try {
    doc = parseJsonc(text);
  } catch (e) {
    throw new UsageError(`tools file ${file} is not valid JSON: ${e.message}`);
  }
  const name = path.parse(file).name;
  let sets = [];
  if (Array.isArray(doc)) {
    const batch = doc.length > 0 && doc.every(isEnvelope);
    sets = [{ server: name, tools: batch ? doc.flatMap((x) => toolsOf(x) || []) : doc }];
  } else if (isEnvelope(doc)) {
    if (doc.error) throw new UsageError(`tools file ${file} holds a JSON-RPC error response, not a tools list`);
    const tools = toolsOf(doc);
    if (tools) sets = [{ server: name, tools }];
  } else if (isObject(doc) && Array.isArray(doc.tools)) {
    sets = [{ server: name, tools: doc.tools }];
  } else if (isObject(doc)) {
    for (const [server, v] of Object.entries(doc)) {
      const tools = toolsOf(v);
      if (tools) sets.push({ server, tools });
    }
  }
  sets = sets.map((s) => ({ server: s.server, tools: s.tools.filter(isTool), file })).filter((s) => s.tools.length);
  if (!sets.length) throw new UsageError(`no tools found in tools file ${file}: ${SHAPES}`);
  return sets;
}

const configErrors = (configs) => configs.filter((c) => c.error).map((c) => ({ path: c.source.path, error: c.error, missing: !!c.source.missing }));

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
  for (const f of findings) f.line = lineOf(textOf[f.file], f.jsonPath) ?? lineOf(textOf[f.file], f.serverPath);
  return {
    version: VERSION,
    generatedAt: new Date().toISOString(),
    live: !!o.connect,
    configs,
    servers: allServers.length,
    toolsScanned: toolSets.reduce((n, t) => n + t.tools.length, 0),
    liveErrors,
    // Config files that could not be read or parsed. When this is not empty
    // the scan is incomplete, and a clean score does not mean the setup is fine.
    errors: configErrors(configs),
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
  const errors = result.errors || configErrors(result.configs);
  return {
    tool: 'mcpsafe',
    version: result.version,
    generatedAt: result.generatedAt,
    complete: errors.length === 0,
    errors,
    score: result.score,
    files: result.configs.map((c) => ({ path: c.source.path, client: c.source.client, scope: c.source.scope, servers: c.servers.map((s) => s.name), error: c.error })),
    servers: result.servers,
    toolsScanned: result.toolsScanned,
    liveErrors: result.liveErrors,
    findings: result.findings,
  };
}
