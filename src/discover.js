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

// Packaged (MSIX) Windows apps keep their AppData under
// %LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache.
function packagesDirs(home) {
  const dirs = [path.join(home, 'AppData', 'Local', 'Packages')];
  if (process.env.LOCALAPPDATA && home === os.homedir()) dirs.push(path.join(process.env.LOCALAPPDATA, 'Packages'));
  return [...new Set(dirs)];
}

// Names of the real (non-symlink) subfolders of dir, or [] when it is missing.
function subdirs(dir) {
  try {
    return fs.readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort();
  } catch {
    return [];
  }
}

const VSCODE_DIRS = ['Code', 'Code - Insiders', 'VSCodium'];
// VS Code forks that Cline and Roo Code are commonly installed in.
const EXTENSION_HOSTS = [...VSCODE_DIRS, 'Cursor', 'Windsurf'];

export function userConfigCandidates(home) {
  const c = [];
  const add = (client, p) => c.push({ client, path: p, scope: 'user' });

  for (const base of appDataDirs(home)) {
    add('Claude Desktop', path.join(base, 'Claude', 'claude_desktop_config.json'));
    for (const code of VSCODE_DIRS) {
      add('VS Code', path.join(base, code, 'User', 'mcp.json'));
      add('VS Code', path.join(base, code, 'User', 'settings.json'));
    }
    add('Cursor', path.join(base, 'Cursor', 'User', 'settings.json'));
    // Settings profiles keep their own mcp.json and settings.json.
    for (const editor of [...VSCODE_DIRS, 'Cursor']) {
      const client = editor === 'Cursor' ? 'Cursor' : 'VS Code';
      const profiles = path.join(base, editor, 'User', 'profiles');
      for (const id of subdirs(profiles)) {
        if (client === 'VS Code') add(client, path.join(profiles, id, 'mcp.json'));
        add(client, path.join(profiles, id, 'settings.json'));
      }
    }
    for (const editor of EXTENSION_HOSTS) {
      const storage = path.join(base, editor, 'User', 'globalStorage');
      add('Cline', path.join(storage, 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'));
      add('Roo Code', path.join(storage, 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'));
    }
  }
  // Claude Desktop from the Microsoft Store or another MSIX install.
  for (const pkgs of packagesDirs(home)) {
    for (const name of subdirs(pkgs).filter((n) => /^Claude_/i.test(n))) {
      add('Claude Desktop', path.join(pkgs, name, 'LocalCache', 'Roaming', 'Claude', 'claude_desktop_config.json'));
    }
  }
  add('Claude Code', path.join(home, '.claude.json'));
  add('Claude Code', path.join(home, '.claude', 'settings.json'));
  add('Cursor', path.join(home, '.cursor', 'mcp.json'));
  add('Windsurf', path.join(home, '.codeium', 'windsurf', 'mcp_config.json'));
  add('Gemini CLI', path.join(home, '.gemini', 'settings.json'));
  const extensions = path.join(home, '.gemini', 'extensions');
  for (const ext of subdirs(extensions)) add('Gemini CLI', path.join(extensions, ext, 'gemini-extension.json'));
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
// Client config folders. They are matched through PROJECT_FILES and not descended into.
const CONFIG_DIRS = ['.cursor', '.vscode', '.claude', '.gemini', '.roo', '.windsurf'];

function exists(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

// Walk a directory (bounded depth) and return project config files found.
export function findProjectConfigs(root, maxDepth = 6) {
  const found = [];
  const check = (client, p) => { if (exists(p)) found.push({ client, path: p, scope: 'project' }); };
  // The folder passed may itself be a config folder, e.g. `mcpsafe .cursor`,
  // also through a symlink with another name.
  let configDir = root;
  if (!CONFIG_DIRS.includes(path.basename(root))) {
    try { configDir = fs.realpathSync(root); } catch { /* keep root */ }
  }
  const rootName = path.basename(configDir);
  if (CONFIG_DIRS.includes(rootName)) {
    for (const [client, rel] of PROJECT_FILES) {
      if (rel.startsWith(`${rootName}/`)) check(client, path.join(path.dirname(configDir), rel));
    }
  } else {
    // A config folder under another name (dotfiles/cursor, Code/User) holds
    // its config directly. settings.json is too common a name to count.
    for (const name of ['mcp.json', 'mcp_config.json', 'cline_mcp_settings.json', 'mcp_settings.json']) {
      const p = path.join(root, name);
      if (exists(p)) found.push({ client: guessClient(p), path: p, scope: 'project' });
    }
  }
  const walk = (dir, depth) => {
    for (const [client, rel] of PROJECT_FILES) check(client, path.join(dir, rel));
    check('Claude Desktop', path.join(dir, 'claude_desktop_config.json'));
    if (path.basename(dir) === 'windsurf') check('Windsurf', path.join(dir, 'mcp_config.json'));
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
  // Cline and Roo Code live inside an editor's folders, so test them first.
  if (s.includes('rooveterinaryinc.roo-cline') || s.includes('/.roo/')) return 'Roo Code';
  if (s.includes('saoudrizwan.claude-dev') || s.endsWith('cline_mcp_settings.json')) return 'Cline';
  if (s.includes('/.cursor/') || s.includes('/Cursor/User/')) return 'Cursor';
  if (s.includes('/.vscode/') || /\/(Code[^/]*|VSCodium)\/User\//.test(s)) return 'VS Code';
  if (s.includes('/.gemini/') || s.endsWith('/gemini-extension.json')) return 'Gemini CLI';
  if (/windsurf/i.test(s)) return 'Windsurf';
  if (s.includes('/.claude') || s.endsWith('.mcp.json')) return 'Claude Code';
  return 'MCP config';
}

// Canonical path, used to recognise one file reached through different
// paths (symlinks, letter case on case-insensitive disks).
function realKey(p) {
  try { return fs.realpathSync.native(p); } catch { /* fall through */ }
  try { return fs.realpathSync(p); } catch { return path.resolve(p); }
}

// The folders Claude Desktop keeps its config in: <base>/Claude/, where base
// is Application Support (macOS), AppData/Roaming or an MSIX LocalCache/Roaming
// (Windows), or .config (Linux).
const DESKTOP_BASES = new Set(['application support', 'roaming', '.config']);

// Config files that only a user's own setup has, never a project: Claude
// Desktop's config in its app folder, Claude Code's ~/.claude.json, an
// editor's User folder, extension storage (Cline, Roo Code) and Windsurf's
// ~/.codeium folder. A claude_desktop_config.json anywhere else (an example
// committed to a repository) is a project file.
// .cursor/mcp.json and .gemini/settings.json are left out: projects have them too.
function isUserShape(p) {
  const parts = String(p).split(/[\\/]/);
  const n = parts.length;
  const base = parts[n - 1].toLowerCase();
  if (base === 'claude_desktop_config.json') {
    return n >= 3 && parts[n - 2].toLowerCase() === 'claude' && DESKTOP_BASES.has(parts[n - 3].toLowerCase());
  }
  if (base === '.claude.json') return true;
  if (base === 'mcp_config.json' && parts[n - 2] === 'windsurf' && parts[n - 3] === '.codeium') return true;
  if (!base.endsWith('.json')) return false;
  for (let i = 1; i < n - 1; i++) if (parts[i] === 'User' && EXTENSION_HOSTS.includes(parts[i - 1])) return true;
  return false;
}

// Whether dir or a folder above it holds .git: a file in a git checkout is a
// repository file, and repository files are project files even when they look
// like a home folder's (a dotfiles repository with .claude.json at its root).
function inGitCheckout(dir, cache) {
  const seen = [];
  let d = path.resolve(dir);
  let hit = false;
  for (;;) {
    if (cache.has(d)) { hit = cache.get(d); break; }
    seen.push(d);
    let git = false;
    try { fs.statSync(path.join(d, '.git')); git = true; } catch { /* none here */ }
    if (git) { hit = true; break; }
    const up = path.dirname(d);
    if (up === d) break;
    d = up;
  }
  for (const x of seen) cache.set(x, hit);
  return hit;
}

function isInside(dir, file) {
  const rel = path.relative(dir, file);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

// Existing user-level configs of the given home folders, keyed by realKey.
function userConfigIndex(homes) {
  const index = new Map();
  for (const h of homes) {
    for (const c of userConfigCandidates(h)) {
      if (!exists(c.path)) continue;
      const k = realKey(c.path);
      if (!index.has(k)) index.set(k, c);
    }
  }
  return index;
}

/**
 * Resolve the list of config files to scan.
 * @param {{paths?: string[], home?: string|null, includeHome?: boolean, depth?: number}} opts
 * depth: how many folder levels below each path to search for project configs.
 *
 * A path that is a user-level config of the home folder (or of the real home
 * folder) keeps user scope, even with includeHome off. A folder that contains
 * such configs, such as the home folder itself, also yields them unless
 * depth is 0.
 */
export function discover({ paths = [], home = os.homedir(), includeHome = true, depth = 6 } = {}) {
  const out = [];
  if (includeHome && home) {
    for (const c of userConfigCandidates(home)) if (exists(c.path)) out.push(c);
  }
  let index;
  const userIndex = () => (index ??= userConfigIndex([...new Set([home || os.homedir(), os.homedir()])]));
  const gitCache = new Map();
  const asUser = (c) => {
    const u = userIndex().get(realKey(c.path));
    if (u) return { client: u.client, path: c.path, scope: 'user' };
    // A file that can only be a user-level config, wherever it sits (another
    // user's home, a backup copy), is not a project file either, unless it
    // sits in a git checkout.
    return isUserShape(c.path) && !inGitCheckout(path.dirname(c.path), gitCache) ? { ...c, scope: 'user' } : c;
  };
  for (const p of paths) {
    const abs = path.resolve(p);
    let st;
    try { st = fs.statSync(abs); } catch { out.push({ client: 'MCP config', path: abs, scope: 'project', missing: true }); continue; }
    if (st.isDirectory()) {
      if (depth > 0) {
        const dir = realKey(abs);
        for (const [k, c] of userIndex()) if (isInside(dir, k)) out.push(c);
        // The folder may be another home folder. If it holds a config that
        // only a home has (~/.claude.json, Claude Desktop, Cline, Roo Code),
        // all its user-level configs keep user scope, ~/.cursor/mcp.json too.
        // A git checkout is a repository, never a home folder.
        if (!inGitCheckout(abs, gitCache)) {
          const own = userConfigCandidates(abs).filter((c) => exists(c.path));
          if (own.some((c) => isUserShape(c.path))) out.push(...own);
        }
      }
      out.push(...findProjectConfigs(abs, depth).map(asUser));
    } else {
      out.push(asUser({ client: guessClient(abs), path: abs, scope: 'project' }));
    }
  }
  // De-duplicate by real path, so a symlinked config is scanned once. The
  // first path found is kept for display; the others are listed as aliases.
  const seen = new Map();
  const result = [];
  for (const c of out) {
    const k = c.missing ? path.resolve(c.path) : realKey(c.path);
    const first = seen.get(k);
    if (!first) {
      const entry = { ...c };
      seen.set(k, entry);
      result.push(entry);
    } else if (path.resolve(first.path) !== path.resolve(c.path)) {
      (first.aliases ??= []).push({ client: c.client, path: c.path });
    }
  }
  return result;
}
