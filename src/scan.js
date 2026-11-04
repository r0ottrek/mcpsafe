import fs from 'node:fs';
import path from 'node:path';
import { discover } from './discover.js';
import { loadConfig } from './parse.js';
import { runChecks, checkTools } from './checks.js';
import { listTools, mcpjsonDisabled } from './live.js';
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
  // The single-server shapes are named after the file (see uniqueToolsNames).
  let fromFile = true;
  if (Array.isArray(doc)) {
    // Tools, saved responses (a batch), or a mix of the two.
    sets = [{ server: name, tools: doc.flatMap((x) => (isEnvelope(x) ? toolsOf(x) || [] : [x])) }];
  } else if (isEnvelope(doc)) {
    if (doc.error) throw new UsageError(`tools file ${file} holds a JSON-RPC error response, not a tools list`);
    const tools = toolsOf(doc);
    if (tools) sets = [{ server: name, tools }];
  } else if (isObject(doc) && (Array.isArray(doc.tools) || (Object.keys(doc).length === 1 && toolsOf(doc)))) {
    // { tools } or { result: { tools } }
    sets = [{ server: name, tools: toolsOf(doc) }];
  } else if (isObject(doc)) {
    fromFile = false;
    // A server whose entry holds no tools list would be skipped without a
    // word, so its tools would never be checked.
    const bad = [];
    for (const [server, v] of Object.entries(doc)) {
      const tools = toolsOf(v);
      if (tools) sets.push({ server, tools }); else bad.push(server);
    }
    if (sets.length && bad.length) {
      throw new UsageError(`tools file ${file}: no tools list for ${bad.map((b) => JSON.stringify(b)).join(', ')} (expected [tools] or {"tools": [...]} for each server)`);
    }
  }
  sets = sets.map((s) => ({ server: s.server, tools: s.tools.filter(isTool), file, ...(fromFile ? { fromFile: true } : {}) })).filter((s) => s.tools.length);
  if (!sets.length) throw new UsageError(`no tools found in tools file ${file}: ${SHAPES}`);
  return sets;
}

// Saved responses in different folders with the same file name (a/tools.json,
// b/tools.json) would all be the server "tools" and merge into one, which hides
// one shadowing the other. Name them after their folder too, and number any
// that still clash.
function uniqueToolsNames(sets) {
  const filesOf = new Map();
  for (const s of sets) {
    if (!filesOf.has(s.server)) filesOf.set(s.server, new Set());
    filesOf.get(s.server).add(path.resolve(s.file));
  }
  const taken = new Set(sets.filter((s) => !s.fromFile || filesOf.get(s.server).size < 2).map((s) => s.server));
  const named = new Map();
  for (const s of sets) {
    if (!s.fromFile || filesOf.get(s.server).size < 2) continue;
    const file = path.resolve(s.file);
    if (!named.has(file)) {
      const base = `${path.basename(path.dirname(file))}/${s.server}`;
      let n = base;
      for (let i = 2; taken.has(n); i++) n = `${base} (${i})`;
      taken.add(n);
      named.set(file, n);
    }
    s.server = named.get(file);
  }
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
  uniqueToolsNames(toolSets);
  if (o.connect) {
    const turnedOff = mcpjsonDisabled(configs);
    for (const s of allServers.filter((x) => !x.disabled && !turnedOff(x))) {
      o.onProgress?.(`Listing tools from "${s.name}"…`);
      try {
        const tools = await listTools(s);
        // srv ties the tools to this exact server, not just to its name.
        toolSets.push({ server: s.name, srv: s, tools, file: s.file });
        if (tools.warning) liveErrors.push({ server: s.name, file: s.file, client: s.client, error: tools.warning });
      } catch (e) {
        liveErrors.push({ server: s.name, file: s.file, client: s.client, error: e.message });
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
