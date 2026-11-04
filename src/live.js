// Optional live mode: connects to each configured server and asks it for its
// tool list, so tool descriptions can be checked for hidden instructions.
// This STARTS the configured servers, so it only runs with --connect.
//
// Servers are launched the way the clients launch them:
// - ${VAR}, ${env:VAR} and ${VAR:-default} in the command, args, env, url and
//   headers are expanded from the environment mcpsafe runs in. Expanded values
//   only go to the server; they are masked in any error message.
// - Project servers start in the project folder (or their own cwd setting).
// - On Windows nothing goes through a shell unquoted. .exe files are started
//   directly. Anything else (npx.cmd and other .cmd/.bat shims) is started as
//   `cmd.exe /d /s /c "<line>"`, where every part of <line> is quoted for
//   CommandLineToArgvW and caret-escaped for cmd.exe, the same way cross-spawn
//   does it.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { mask } from './secrets.js';

const PROTOCOL = '2025-06-18';
const CLIENT = { name: 'mcpsafe', version: '1.0.0' };
export const MAX_PAGES = 100;

function withTimeout(promise, ms, label) {
  let t;
  return Promise.race([
    promise.finally(() => clearTimeout(t)),
    new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${label} timed out after ${ms / 1000}s`)), ms); }),
  ]);
}

// ---------------------------------------------------------------------------
// Variable expansion

const NAME = '[A-Za-z_][A-Za-z0-9_]*';
const PLAIN = new RegExp(`^(?:env:)?(${NAME})$`);
const WITH_DEFAULT = new RegExp(`^(${NAME}):-([\\s\\S]*)$`);

/**
 * Expands ${VAR}, ${env:VAR}, ${VAR:-default}, ${userHome} and
 * ${workspaceFolder} in one string. References that cannot be resolved (unset
 * variables, ${input:...}) are left as they are and recorded in ctx.unresolved.
 * Values taken from the environment are recorded in ctx.secrets so that error
 * messages can mask them.
 */
export function expandVars(value, ctx) {
  return String(value).replace(/\$\{([^}]*)\}/g, (whole, inner) => {
    if (inner === 'userHome' && ctx.home) return ctx.home;
    if (inner === 'workspaceFolder' && ctx.workspace) return ctx.workspace;
    let m = PLAIN.exec(inner);
    if (m) {
      const v = ctx.env[m[1]];
      if (v !== undefined) { ctx.secrets?.add(v); return v; }
    } else if ((m = WITH_DEFAULT.exec(inner))) {
      const v = ctx.env[m[1]];
      if (v) { ctx.secrets?.add(v); return v; }
      return m[2];
    }
    ctx.unresolved?.add(whole);
    ctx.misses = (ctx.misses || 0) + 1;
    return whole;
  });
}

// ---------------------------------------------------------------------------
// Where and how a stdio server is started

const CONFIG_DIRS = new Set(['.cursor', '.vscode', '.roo', '.gemini', '.claude', '.windsurf']);

/** The project folder a server belongs to, or null for user-level servers. */
export function projectRoot(server) {
  const m = /^projects\["(.*?)"\]\.mcpServers\./.exec(server.jsonPath || '');
  if (m) return m[1];
  if (server.scope !== 'project' || !server.file) return null;
  const dir = path.dirname(server.file);
  return CONFIG_DIRS.has(path.basename(dir)) ? path.dirname(dir) : dir;
}

function normDir(p) {
  const r = path.resolve(p);
  return process.platform === 'win32' ? r.replace(/\//g, '\\').toLowerCase() : r;
}

/**
 * Claude Code lets a user turn off servers from a project's .mcp.json with
 * disabledMcpjsonServers, either per project in ~/.claude.json or in a settings
 * file. Returns a function that tells whether a server was turned off that way.
 */
export function mcpjsonDisabled(configs) {
  const byRoot = new Map();
  const add = (root, list) => {
    if (!Array.isArray(list)) return;
    const k = root == null ? '*' : normDir(root);
    if (!byRoot.has(k)) byRoot.set(k, new Set());
    for (const n of list) byRoot.get(k).add(String(n));
  };
  for (const c of configs) {
    const doc = c.doc;
    if (!doc || typeof doc !== 'object' || c.source?.client !== 'Claude Code') continue;
    const file = c.source.path;
    if (doc.projects && typeof doc.projects === 'object') {
      for (const [root, cfg] of Object.entries(doc.projects)) add(root, cfg?.disabledMcpjsonServers);
    }
    const dir = path.dirname(file);
    if (path.basename(dir) === '.claude') {
      // <project>/.claude/settings*.json applies to that project; ~/.claude/settings.json to all.
      const isUser = c.source.scope === 'user';
      add(isUser ? null : path.dirname(dir), doc.disabledMcpjsonServers);
    }
  }
  return (server) => {
    if (path.basename(server.file || '') !== '.mcp.json') return false;
    const root = normDir(path.dirname(server.file));
    return !!(byRoot.get(root)?.has(server.name) || byRoot.get('*')?.has(server.name));
  };
}

const META = /([()\][%!^"`<>&|;, *?])/g;

function escapeCommand(s) {
  return s.replace(META, '^$1');
}

// Quote for CommandLineToArgvW, then escape for cmd.exe (from cross-spawn).
function escapeArgument(arg, doubleEscape) {
  let a = String(arg);
  a = a.replace(/(?=(\\+?)?)\1"/g, '$1$1\\"');
  a = a.replace(/(?=(\\+?)?)\1$/, '$1$1');
  a = `"${a}"`;
  a = a.replace(META, '^$1');
  if (doubleEscape) a = a.replace(META, '^$1');
  return a;
}

function getEnv(env, key) {
  const k = Object.keys(env).find((x) => x.toUpperCase() === key);
  return k ? env[k] : undefined;
}

function isFile(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

/** Finds a command on PATH with PATHEXT, as cmd.exe would. Null when not found. */
export function resolveWindowsCommand(command, env, exists = isFile) {
  const exts = String(getEnv(env, 'PATHEXT') || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  const names = (base) => [...(path.win32.extname(base) ? [base] : []), ...exts.map((e) => base + e.toLowerCase())];
  if (/[\\/]/.test(command) || path.win32.isAbsolute(command)) return names(command).find(exists) || null;
  for (const dir of String(getEnv(env, 'PATH') || '').split(';').filter(Boolean)) {
    const hit = names(path.win32.join(dir.replace(/^"(.*)"$/, '$1'), command)).find(exists);
    if (hit) return hit;
  }
  return null;
}

/** How to spawn a command so that no argument is re-parsed by a shell. */
export function spawnPlan(command, args, { platform = process.platform, env = process.env, exists = isFile } = {}) {
  if (platform !== 'win32') return { file: command, args, verbatim: false };
  const resolved = resolveWindowsCommand(command, env, exists) || command;
  if (/\.(?:com|exe)$/i.test(resolved)) return { file: resolved, args, verbatim: false };
  // npm's cmd-shims pass %* on to another command, which parses it once more.
  const doubleEscape = /node_modules[\\/]\.bin[\\/][^\\/]+\.cmd$/i.test(resolved);
  const line = [escapeCommand(path.win32.normalize(resolved)), ...args.map((a) => escapeArgument(a, doubleEscape))].join(' ');
  return { file: getEnv(env, 'COMSPEC') || 'cmd.exe', args: ['/d', '/s', '/c', `"${line}"`], verbatim: true };
}

function setEnv(env, key, value) {
  if (process.platform === 'win32') for (const k of Object.keys(env)) if (k.toUpperCase() === key.toUpperCase()) delete env[k];
  env[key] = value;
}

function prepare(server, ctx) {
  if (server.transport === 'stdio') {
    if (!server.command) throw new Error('no command');
    const command = expandVars(server.command, ctx);
    const args = (server.args || []).map((a) => expandVars(a, ctx));
    const env = { ...process.env };
    for (const [k, v] of Object.entries(server.env || {})) {
      if (v == null || typeof v === 'object') continue;
      const before = ctx.misses || 0;
      const value = expandVars(String(v), ctx);
      // An unresolved reference is not passed on literally: the server keeps
      // whatever it inherits, which is what most clients do for an unset value.
      if ((ctx.misses || 0) > before) continue;
      if (String(v).length >= 8) ctx.secrets.add(String(v));
      setEnv(env, k, value);
    }
    const root = projectRoot(server);
    let cwd = server.cwd ? expandVars(server.cwd, ctx) : root;
    if (cwd && root && !path.isAbsolute(cwd)) cwd = path.resolve(root, cwd);
    if (cwd) {
      let ok = false;
      try { ok = fs.statSync(cwd).isDirectory(); } catch { /* missing */ }
      if (!ok) throw new Error(`working folder ${cwd} does not exist`);
    }
    return { cwd: cwd || undefined, env, plan: spawnPlan(command, args, { env }) };
  }
  const before = ctx.misses || 0;
  const url = expandVars(server.url || '', ctx);
  if ((ctx.misses || 0) > before) throw new Error('the server URL refers to a variable that is not set');
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error();
  } catch {
    throw new Error('the server URL is not a valid http or https URL');
  }
  const headers = {};
  for (const [k, v] of Object.entries(server.headers || {})) {
    if (v == null || typeof v === 'object') continue;
    const b = ctx.misses || 0;
    const value = expandVars(String(v), ctx);
    if ((ctx.misses || 0) > b) continue;
    if (String(v).length >= 8) ctx.secrets.add(String(v));
    headers[k] = value;
  }
  return { url, headers };
}

// ---------------------------------------------------------------------------
// JSON-RPC message handling shared by all transports

// Routes one incoming message: responses resolve the pending request with the
// same id; requests from the server (which use their own id space) are never
// taken as responses. A ping is answered, any other request is declined.
function dispatch(msg, pending, reply) {
  if (Array.isArray(msg)) { for (const m of msg) dispatch(m, pending, reply); return; }
  if (!msg || typeof msg !== 'object') return;
  if (typeof msg.method === 'string') {
    if (msg.id != null && reply) {
      reply(msg.method === 'ping'
        ? { jsonrpc: '2.0', id: msg.id, result: {} }
        : { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Method not found' } });
    }
    return;
  }
  if (msg.id != null && ('result' in msg || 'error' in msg) && pending.has(msg.id)) {
    const r = pending.get(msg.id);
    pending.delete(msg.id);
    r(msg);
  }
}

function settle(m) {
  if (m.error) throw new Error(typeof m.error.message === 'string' && m.error.message ? m.error.message : 'request failed');
  return m.result;
}

function parseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

// Reads a text/event-stream body event by event. Data lines of one event are
// joined with "\n", as the SSE format defines.
export async function* sseEvents(body) {
  const reader = body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  let data = [];
  let event = '';
  let done = false;
  try {
    while (!done) {
      const r = await reader.read();
      if (r.done) { done = true; buf += dec.decode(); buf += '\n\n'; } else buf += dec.decode(r.value, { stream: true });
      for (;;) {
        const m = /\r\n|\r|\n/.exec(buf);
        if (!m) break;
        // A lone \r at the end may be the first half of \r\n.
        if (m[0] === '\r' && m.index === buf.length - 1 && !done) break;
        const line = buf.slice(0, m.index);
        buf = buf.slice(m.index + m[0].length);
        if (line === '') {
          if (data.length) yield { event: event || 'message', data: data.join('\n') };
          data = [];
          event = '';
          continue;
        }
        if (line.startsWith(':')) continue;
        const c = line.indexOf(':');
        const field = c < 0 ? line : line.slice(0, c);
        let val = c < 0 ? '' : line.slice(c + 1);
        if (val.startsWith(' ')) val = val.slice(1);
        if (field === 'data') data.push(val);
        else if (field === 'event') event = val;
      }
    }
  } finally {
    reader.cancel().catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Transports

function stdioSession(server, prep) {
  const { plan } = prep;
  const child = spawn(plan.file, plan.args, {
    env: prep.env, cwd: prep.cwd, stdio: ['pipe', 'pipe', 'ignore'], windowsVerbatimArguments: plan.verbatim, windowsHide: true,
  });
  const pending = new Map();
  let exitErr = null;
  let closed = false;
  // A server that exits at once makes writes fail with EPIPE. That must not
  // crash mcpsafe: the exit is reported through 'exit'/'close' below.
  child.stdin.on('error', () => {});
  child.stdout.on('error', () => {});
  const write = (msg) => {
    if (exitErr || closed || !child.stdin.writable) return;
    try { child.stdin.write(`${JSON.stringify(msg)}\n`); } catch { /* reported by exit */ }
  };
  let buf = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) dispatch(parseJson(line), pending, write);
    }
  });
  const fail = (e) => {
    if (!exitErr) exitErr = e;
    for (const r of pending.values()) r({ error: { message: exitErr.message } });
    pending.clear();
  };
  let exitMsg = null;
  child.on('error', fail);
  child.on('exit', (code, signal) => {
    exitMsg = signal ? `server exited (${signal})` : `server exited with code ${code}`;
    // Give buffered output a moment to arrive; 'close' usually comes first.
    setTimeout(() => fail(new Error(exitMsg)), 100).unref();
  });
  child.on('close', () => fail(new Error(exitMsg || 'server closed its output')));
  let nextId = 1;
  const cleanup = () => { try { child.stdout.destroy(); } catch { /* ignore */ } };
  return {
    request(method, params) {
      if (exitErr) return Promise.reject(exitErr);
      if (closed) return Promise.reject(new Error('session closed'));
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, (m) => { try { resolve(settle(m)); } catch (e) { reject(e); } });
        write({ jsonrpc: '2.0', id, method, params });
      });
    },
    notify(method, params) { write({ jsonrpc: '2.0', method, params }); },
    // MCP stdio shutdown: close stdin, then SIGTERM, then SIGKILL.
    close() {
      if (closed) return;
      closed = true;
      try { child.stdin.end(); } catch { /* ignore */ }
      if (child.exitCode !== null || child.signalCode !== null || child.pid == null) { cleanup(); return; }
      const term = setTimeout(() => {
        if (process.platform === 'win32') {
          // cmd.exe may sit between us and the server; end the whole tree.
          try { spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true }).on('error', () => {}); } catch { /* ignore */ }
        } else {
          try { child.kill('SIGTERM'); } catch { /* ignore */ }
        }
      }, 500);
      let last;
      const kill = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* ignore */ }
        cleanup();
        // Wait for the exit so the process is reaped, but never hang on it.
        last = setTimeout(() => child.unref(), 1000);
      }, 2500);
      child.once('exit', () => { clearTimeout(term); clearTimeout(kill); clearTimeout(last); cleanup(); });
    },
  };
}

function httpError(status) {
  const e = new Error(`HTTP ${status}`);
  e.status = status;
  return e;
}

// Streamable HTTP.
function httpSession(server, prep) {
  const ac = new AbortController();
  let sessionId = null;
  let protocol = PROTOCOL;
  let nextId = 1;
  const post = async (body) => {
    const h = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'mcp-protocol-version': protocol, ...prep.headers };
    if (sessionId) h['mcp-session-id'] = sessionId;
    const res = await fetch(prep.url, { method: 'POST', headers: h, body: JSON.stringify(body), signal: ac.signal });
    sessionId = res.headers.get('mcp-session-id') || sessionId;
    return res;
  };
  const reply = (msg) => { post(msg).then((r) => r.body?.cancel()).catch(() => {}); };
  return {
    async request(method, params) {
      const id = nextId++;
      const res = await post({ jsonrpc: '2.0', id, method, params });
      if (!res.ok) { res.body?.cancel().catch(() => {}); throw httpError(res.status); }
      const type = res.headers.get('content-type') || '';
      const pending = new Map();
      let found = null;
      pending.set(id, (m) => { found = m; });
      if (type.includes('text/event-stream')) {
        // Stop reading as soon as the response arrives: the stream may stay open.
        for await (const ev of sseEvents(res.body)) {
          if (ev.event !== 'message') continue;
          dispatch(parseJson(ev.data), pending, reply);
          if (found) break;
        }
      } else {
        dispatch(parseJson(await res.text()), pending, reply);
      }
      if (!found) throw new Error('no response');
      return settle(found);
    },
    notify(method, params) { return post({ jsonrpc: '2.0', method, params }).then((r) => r.body?.cancel()).catch(() => {}); },
    setProtocolVersion(v) { protocol = v; },
    close() { ac.abort(); },
  };
}

// The older HTTP+SSE transport (protocol 2024-11-05, and Gemini CLI's `url`):
// a GET opens an event stream whose first event names the URL to POST to;
// responses come back on the stream.
function sseSession(server, prep) {
  const ac = new AbortController();
  const pending = new Map();
  let nextId = 1;
  let endpoint = null;
  let streamErr = null;
  let onReady;
  let onFail;
  const ready = new Promise((res, rej) => { onReady = res; onFail = rej; });
  ready.catch(() => {});
  const fail = (e) => {
    if (!streamErr) streamErr = e;
    onFail(streamErr);
    for (const r of pending.values()) r({ error: { message: streamErr.message } });
    pending.clear();
  };
  const post = async (body) => {
    const res = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json', ...prep.headers }, body: JSON.stringify(body), signal: ac.signal });
    res.body?.cancel().catch(() => {});
    if (!res.ok) throw httpError(res.status);
  };
  const reply = (msg) => { post(msg).catch(() => {}); };
  (async () => {
    const res = await fetch(prep.url, { headers: { accept: 'text/event-stream', ...prep.headers }, signal: ac.signal });
    if (!res.ok) { res.body?.cancel().catch(() => {}); throw httpError(res.status); }
    if (!(res.headers.get('content-type') || '').includes('text/event-stream')) {
      res.body?.cancel().catch(() => {});
      throw new Error('the server did not open an event stream');
    }
    for await (const ev of sseEvents(res.body)) {
      if (ev.event === 'endpoint' && !endpoint) {
        let u;
        try { u = new URL(ev.data.trim(), prep.url); } catch { throw new Error('the server sent an invalid message endpoint'); }
        // Never send the configured headers (often credentials) to another host.
        if (u.origin !== new URL(prep.url).origin) throw new Error('the server asked for messages to go to a different host, which mcpsafe does not follow');
        endpoint = u.href;
        onReady();
      } else if (ev.event === 'message') {
        dispatch(parseJson(ev.data), pending, endpoint ? reply : null);
      }
    }
    throw new Error('the server closed the event stream');
  })().catch((e) => fail(e?.name === 'AbortError' ? new Error('session closed') : e));
  return {
    async request(method, params) {
      await ready;
      if (streamErr) throw streamErr;
      const id = nextId++;
      const p = new Promise((resolve, reject) => {
        pending.set(id, (m) => { try { resolve(settle(m)); } catch (e) { reject(e); } });
      });
      p.catch(() => {});
      try { await post({ jsonrpc: '2.0', id, method, params }); } catch (e) { pending.delete(id); throw e; }
      return p;
    },
    notify(method, params) { return ready.then(() => post({ jsonrpc: '2.0', method, params })).catch(() => {}); },
    close() { ac.abort(); },
  };
}

// ---------------------------------------------------------------------------

function cleanMessage(e, ctx) {
  let msg = e?.message || String(e);
  for (const v of [...ctx.secrets].filter((s) => s && s.length >= 4).sort((a, b) => b.length - a.length)) {
    msg = msg.split(v).join(mask(v));
  }
  if (ctx.unresolved.size) msg += ` (not set: ${[...ctx.unresolved].join(', ')})`;
  return msg;
}

/**
 * Starts or connects to a server and returns its tools. The returned array may
 * carry a `warning` when the list was cut short. Error messages never contain
 * values expanded from the environment.
 */
export async function listTools(server, timeoutMs = 20000) {
  const ctx = { env: process.env, home: os.homedir(), workspace: projectRoot(server), unresolved: new Set(), secrets: new Set(), misses: 0 };
  let session = null;
  let done = false;
  const open = (kind, prep) => {
    if (done) throw new Error('cancelled');
    session?.close();
    session = kind === 'stdio' ? stdioSession(server, prep) : kind === 'sse' ? sseSession(server, prep) : httpSession(server, prep);
    return session.request('initialize', { protocolVersion: PROTOCOL, capabilities: {}, clientInfo: CLIENT });
  };
  const run = async () => {
    const prep = prepare(server, ctx);
    let init;
    if (server.transport === 'http') {
      try {
        init = await open('http', prep);
      } catch (e) {
        // A 4xx on the first POST is how an older SSE-only server answers.
        if (![400, 404, 405].includes(e.status)) throw e;
        try {
          init = await open('sse', prep);
        } catch (e2) {
          throw new Error(`${e.message}, and connecting with the older SSE transport failed too: ${e2.message}`);
        }
      }
    } else {
      init = await open(server.transport === 'sse' ? 'sse' : 'stdio', prep);
    }
    if (typeof init?.protocolVersion === 'string') session.setProtocolVersion?.(init.protocolVersion);
    await session.notify('notifications/initialized', {});
    const tools = [];
    const seen = new Set();
    let cursor;
    let warning = null;
    for (let page = 0; ; page++) {
      if (page >= MAX_PAGES) { warning = `listed only the first ${MAX_PAGES} pages of tools; the rest were not checked`; break; }
      const r = await session.request('tools/list', cursor ? { cursor } : {});
      if (Array.isArray(r?.tools)) tools.push(...r.tools.filter((t) => t && typeof t === 'object'));
      cursor = r?.nextCursor;
      if (cursor == null || cursor === '') break;
      if (seen.has(cursor)) { warning = 'the server repeated a page of its tool list; later pages were not checked'; break; }
      seen.add(cursor);
    }
    if (warning) tools.warning = warning;
    return tools;
  };
  try {
    return await withTimeout(run(), timeoutMs, `${server.name}`);
  } catch (e) {
    throw new Error(cleanMessage(e, ctx));
  } finally {
    done = true;
    session?.close();
  }
}
