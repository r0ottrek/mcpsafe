// Reads a config file and normalizes every MCP server definition in it.
import fs from 'node:fs';
import { parseJsonc, stripJsonc } from './jsonc.js';

const HTTP_TYPES = new Set(['http', 'streamable-http', 'streamablehttp', 'streamable_http']);

// Transport of a remote server. An explicit type wins. Gemini CLI uses `url`
// for SSE and `httpUrl` for Streamable HTTP (and prefers httpUrl when both
// are set); other clients use `url` for Streamable HTTP.
function remoteTransport(def, source) {
  const type = [def.type, def.transport, def.transportType].find((t) => typeof t === 'string')?.toLowerCase();
  if (type === 'sse') return 'sse';
  if (HTTP_TYPES.has(type)) return 'http';
  if (source.client === 'Gemini CLI' && str(def.url) && !str(def.httpUrl)) return 'sse';
  return 'http';
}

// String() throws on an object such as {"toString": 1}, so values of the wrong
// type become JSON text (or are dropped) instead of reaching the reports.
function safeString(v) {
  if (typeof v === 'string') return v;
  if (v === null || typeof v !== 'object') return String(v);
  try { return JSON.stringify(v); } catch { return ''; }
}
const str = (v) => (typeof v === 'string' && v ? v : null);

function normServer(name, def, source, jsonPath) {
  if (!def || typeof def !== 'object') return null;
  const gemini = source.client === 'Gemini CLI';
  // Only string urls count: an object or array here is not an address and cannot be connected to.
  const url = (gemini && str(def.httpUrl)) || str(def.url) || str(def.serverUrl) || str(def.httpUrl) || str(def.endpoint) || null;
  let transport = 'stdio';
  if (url) transport = remoteTransport(def, source);
  const args = Array.isArray(def.args) ? def.args.map(safeString) : [];
  return {
    name,
    client: source.client,
    file: source.path,
    scope: source.scope,
    jsonPath,
    transport,
    command: typeof def.command === 'string' ? def.command : null,
    args,
    env: def.env && typeof def.env === 'object' ? def.env : {},
    url,
    headers: def.headers && typeof def.headers === 'object' ? def.headers : {},
    cwd: str(def.cwd),
    disabled: def.disabled === true || def.enabled === false,
    autoApprove: [def.autoApprove, def.alwaysAllow].flatMap((v) => (Array.isArray(v) ? v : [])).map((t) => (t === true ? t : safeString(t))),
    trust: def.trust === true,
    raw: def,
  };
}

function collect(obj, source, prefix, out) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return;
  for (const [name, def] of Object.entries(obj)) {
    const s = normServer(name, def, source, `${prefix}.${name}`);
    if (s) out.push(s);
  }
}

export function extractServers(doc, source) {
  const servers = [];
  if (!doc || typeof doc !== 'object') return servers;
  collect(doc.mcpServers, source, 'mcpServers', servers);
  // VS Code mcp.json uses "servers"; VS Code settings.json uses "mcp.servers".
  if (doc.servers && /mcp\.json$/i.test(source.path)) collect(doc.servers, source, 'servers', servers);
  if (doc.mcp && typeof doc.mcp === 'object') collect(doc.mcp.servers, source, 'mcp.servers', servers);
  if (doc['mcp.servers']) collect(doc['mcp.servers'], source, '"mcp.servers"', servers);
  // Claude Code ~/.claude.json keeps per-project servers under projects.<path>.mcpServers
  if (doc.projects && typeof doc.projects === 'object') {
    for (const [proj, cfg] of Object.entries(doc.projects)) {
      if (cfg && cfg.mcpServers) collect(cfg.mcpServers, source, `projects["${proj}"].mcpServers`, servers);
    }
  }
  return servers;
}

export function loadConfig(source) {
  const result = { source, text: null, doc: null, servers: [], error: null, mode: null };
  if (source.missing) { result.error = 'File not found'; return result; }
  try {
    const st = fs.statSync(source.path);
    result.mode = st.mode & 0o777;
    result.text = fs.readFileSync(source.path, 'utf8');
  } catch (e) {
    result.error = `Could not read file: ${e.code || e.message}`;
    return result;
  }
  // An empty file, or one with only comments (a fresh VS Code settings.json), has no servers.
  if (!stripJsonc(result.text.replace(/^﻿/, '')).trim()) return result;
  try {
    result.doc = parseJsonc(result.text);
  } catch (e) {
    result.error = `Could not parse JSON: ${e.message}`;
    return result;
  }
  result.servers = extractServers(result.doc, source);
  return result;
}
