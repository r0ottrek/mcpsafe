// Reads a config file and normalizes every MCP server definition in it.
import fs from 'node:fs';
import { parseJsonc } from './jsonc.js';

function normServer(name, def, source, jsonPath) {
  if (!def || typeof def !== 'object') return null;
  const url = def.httpUrl || def.url || def.serverUrl || def.endpoint || null;
  const type = def.type || def.transport || def.transportType;
  let transport = 'stdio';
  if (def.httpUrl) transport = 'http';
  else if (url && type === 'sse') transport = 'sse';
  // Gemini CLI: `url` is an SSE endpoint and `httpUrl` is Streamable HTTP,
  // unless an explicit type says otherwise.
  else if (url && source.client === 'Gemini CLI' && def.url && !/^(?:http|streamable-?http)$/i.test(String(type || ''))) transport = 'sse';
  else if (url) transport = 'http';
  const args = Array.isArray(def.args) ? def.args.map(String) : [];
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
    cwd: def.cwd || null,
    disabled: def.disabled === true || def.enabled === false,
    autoApprove: [def.autoApprove, def.alwaysAllow].flatMap((v) => (Array.isArray(v) ? v : [])),
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
  if (!result.text.trim()) return result;
  try {
    result.doc = parseJsonc(result.text);
  } catch (e) {
    result.error = `Could not parse JSON: ${e.message}`;
    return result;
  }
  result.servers = extractServers(result.doc, source);
  return result;
}
