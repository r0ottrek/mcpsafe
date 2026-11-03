// Optional live mode: connects to each configured server and asks it for its
// tool list, so tool descriptions can be checked for hidden instructions.
// This STARTS the configured servers, so it only runs with --connect.
import { spawn } from 'node:child_process';

const PROTOCOL = '2025-06-18';
const CLIENT = { name: 'mcpsafe', version: '1.0.0' };

function withTimeout(promise, ms, label) {
  let t;
  return Promise.race([
    promise.finally(() => clearTimeout(t)),
    new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${label} timed out after ${ms / 1000}s`)), ms); }),
  ]);
}

function stdioSession(server) {
  const env = { ...process.env };
  for (const [k, v] of Object.entries(server.env)) if (!/\$\{/.test(String(v))) env[k] = String(v);
  const child = spawn(server.command, server.args, {
    env, cwd: server.cwd || undefined, stdio: ['pipe', 'pipe', 'ignore'], shell: process.platform === 'win32',
  });
  let buf = '';
  const pending = new Map();
  let exitErr = null;
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }
      if (msg.id != null && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    }
  });
  const fail = (e) => { exitErr = e; for (const r of pending.values()) r({ error: { message: e.message } }); pending.clear(); };
  child.on('error', fail);
  child.on('exit', (code) => fail(new Error(`server exited with code ${code}`)));
  let nextId = 1;
  return {
    request(method, params) {
      if (exitErr) return Promise.reject(exitErr);
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, (m) => (m.error ? reject(new Error(m.error.message || 'request failed')) : resolve(m.result)));
        child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      });
    },
    notify(method, params) { if (!exitErr) child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`); },
    close() { try { child.kill(); } catch { /* ignore */ } },
  };
}

function httpSession(server) {
  let sessionId = null;
  let nextId = 1;
  const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'mcp-protocol-version': PROTOCOL };
  for (const [k, v] of Object.entries(server.headers)) if (!/\$\{/.test(String(v))) headers[k] = String(v);
  const post = async (body) => {
    const h = { ...headers };
    if (sessionId) h['mcp-session-id'] = sessionId;
    const res = await fetch(server.url, { method: 'POST', headers: h, body: JSON.stringify(body) });
    sessionId = res.headers.get('mcp-session-id') || sessionId;
    return res;
  };
  return {
    async request(method, params) {
      const id = nextId++;
      const res = await post({ jsonrpc: '2.0', id, method, params });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const type = res.headers.get('content-type') || '';
      const text = await res.text();
      const msgs = type.includes('text/event-stream')
        ? text.split('\n').filter((l) => l.startsWith('data:')).map((l) => { try { return JSON.parse(l.slice(5)); } catch { return null; } })
        : [JSON.parse(text)];
      const m = msgs.flat().find((x) => x && x.id === id);
      if (!m) throw new Error('no response');
      if (m.error) throw new Error(m.error.message);
      return m.result;
    },
    notify(method, params) { post({ jsonrpc: '2.0', method, params }).catch(() => {}); },
    close() {},
  };
}

export async function listTools(server, timeoutMs = 20000) {
  if (server.transport === 'sse') throw new Error('legacy SSE transport is not supported in live mode');
  if (server.transport === 'stdio' && !server.command) throw new Error('no command');
  const session = server.transport === 'stdio' ? stdioSession(server) : httpSession(server);
  try {
    return await withTimeout((async () => {
      await session.request('initialize', { protocolVersion: PROTOCOL, capabilities: {}, clientInfo: CLIENT });
      session.notify('notifications/initialized', {});
      const tools = [];
      let cursor;
      for (let page = 0; page < 20; page++) {
        const r = await session.request('tools/list', cursor ? { cursor } : {});
        tools.push(...(r?.tools || []));
        cursor = r?.nextCursor;
        if (!cursor) break;
      }
      return tools;
    })(), timeoutMs, `${server.name}`);
  } finally {
    session.close();
  }
}
