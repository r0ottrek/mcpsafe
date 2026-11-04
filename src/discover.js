// Finds MCP and AI agent config files on this machine or inside a project.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Config base dirs used by desktop apps on macOS, Windows and Linux.
// We check all of them regardless of platform: it is cheap and keeps the
// scanner testable with a fake home directory.
function appDataDirs(home) {
  const dirs = [
    path.join(home, 'Library', 'Application Support'),
    path.join(home, 'AppData', 'Roaming'),
    path.join(home, '.config'),
  ];
  if (process.env.APPDATA && home === os.homedir()) dirs.push(process.env.APPDATA);
  return [...new Set(dirs)];
}

export function userConfigCandidates(home) {
  const c = [];
  const add = (client, p) => c.push({ client, path: p, scope: 'user' });

  for (const base of appDataDirs(home)) {
    add('Claude Desktop', path.join(base, 'Claude', 'claude_desktop_config.json'));
    for (const code of ['Code', 'Code - Insiders', 'VSCodium']) {
      add('VS Code', path.join(base, code, 'User', 'mcp.json'));
      add('VS Code', path.join(base, code, 'User', 'settings.json'));
      add('Cline', path.join(base, code, 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'));
      add('Roo Code', path.join(base, code, 'User', 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'));
    }
    add('Cursor', path.join(base, 'Cursor', 'User', 'settings.json'));
  }
  add('Claude Code', path.join(home, '.claude.json'));
  add('Claude Code', path.join(home, '.claude', 'settings.json'));
  add('Cursor', path.join(home, '.cursor', 'mcp.json'));
  add('Windsurf', path.join(home, '.codeium', 'windsurf', 'mcp_config.json'));
  add('Gemini CLI', path.join(home, '.gemini', 'settings.json'));
  return c;
}

// Project-level config files, relative to a project root.
export const PROJECT_FILES = [
  ['Claude Code', '.mcp.json'],
  ['Claude Code', '.claude/settings.json'],
  ['Claude Code', '.claude/settings.local.json'],
  ['Cursor', '.cursor/mcp.json'],
  ['VS Code', '.vscode/mcp.json'],
  ['VS Code', '.vscode/settings.json'],
  ['Gemini CLI', '.gemini/settings.json'],
  ['Roo Code', '.roo/mcp.json'],
  ['Windsurf', '.windsurf/mcp_config.json'],
];

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'vendor', '.venv', 'venv', '__pycache__', 'target', '.next', 'coverage']);

function exists(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

const CONFIG_DIRS = ['.cursor', '.vscode', '.claude', '.gemini', '.roo', '.windsurf'];

// Config files that sit directly in a folder passed by the user, for when
// that folder is itself a client config folder such as ~/.cursor, ~/.claude
// or the Claude Desktop folder.
function rootConfigs(root) {
  const base = path.basename(root);
  const files = PROJECT_FILES.filter(([, rel]) => rel.split('/')[0] === base).map(([client, rel]) => [client, rel.split('/').slice(1).join('/')]);
  if (base.toLowerCase() === 'windsurf') files.push(['Windsurf', 'mcp_config.json']);
  return files.map(([client, rel]) => ({ client, path: path.join(root, rel), scope: 'project' })).filter((c) => exists(c.path));
}

// Walk a directory (bounded depth) and return project config files found.
export function findProjectConfigs(root, maxDepth = 6) {
  const found = rootConfigs(root);
  const walk = (dir, depth) => {
    // The Claude Desktop file name is distinctive enough to match anywhere,
    // so a copied app config folder (e.g. AppData/Roaming) is found too.
    for (const [client, rel] of [...PROJECT_FILES, ['Claude Desktop', 'claude_desktop_config.json']]) {
      const p = path.join(dir, rel);
      if (exists(p)) found.push({ client, path: p, scope: 'project' });
    }
    if (depth >= maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (!e.isDirectory() || e.isSymbolicLink() || SKIP_DIRS.has(e.name)) continue;
      // Config folders are matched above; do not descend into them.
      if (CONFIG_DIRS.includes(e.name)) continue;
      walk(path.join(dir, e.name), depth + 1);
    }
  };
  walk(root, 0);
  return found;
}

function guessClient(p) {
  const s = p.replace(/\\/g, '/');
  if (s.endsWith('claude_desktop_config.json')) return 'Claude Desktop';
  if (s.includes('/.cursor/')) return 'Cursor';
  if (s.includes('/.vscode/') || /\/Code[^/]*\/User\//.test(s)) return 'VS Code';
  if (s.includes('/.gemini/')) return 'Gemini CLI';
  if (s.includes('windsurf')) return 'Windsurf';
  if (s.includes('cline')) return 'Cline';
  if (s.includes('/.claude') || s.endsWith('.mcp.json')) return 'Claude Code';
  return 'MCP config';
}

/**
 * Resolve the list of config files to scan.
 * @param {{paths?: string[], home?: string|null, includeHome?: boolean, depth?: number}} opts
 * depth: how many folder levels below each path to search for project configs.
 */
export function discover({ paths = [], home = os.homedir(), includeHome = true, depth = 6 } = {}) {
  const out = [];
  if (includeHome && home) {
    for (const c of userConfigCandidates(home)) if (exists(c.path)) out.push(c);
  }
  for (const p of paths) {
    const abs = path.resolve(p);
    let st;
    try { st = fs.statSync(abs); } catch { out.push({ client: 'MCP config', path: abs, scope: 'project', missing: true }); continue; }
    if (st.isDirectory()) out.push(...findProjectConfigs(abs, depth));
    else out.push({ client: guessClient(abs), path: abs, scope: 'project' });
  }
  // De-duplicate by resolved path.
  const seen = new Set();
  return out.filter((c) => {
    const k = path.resolve(c.path);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
