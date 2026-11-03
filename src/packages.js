// Works out which package (npm, PyPI, Docker image) a server launches, and
// whether that reference is pinned to an exact version.
import path from 'node:path';

const SEMVER = /^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/;
const PY_EXACT = /^\d+(\.\d+)*([a-z]+\d*)?(\.post\d+)?(\.dev\d+)?$/i;
const COMMIT = /^[0-9a-f]{40}$/i;

export function baseCommand(cmd) {
  if (!cmd) return '';
  return path.basename(cmd.replace(/\\/g, '/')).toLowerCase().replace(/\.(cmd|exe|bat|ps1)$/, '');
}

// Unwrap `cmd /c npx ...` and `wsl npx ...` style launchers.
export function effectiveCommand(server) {
  let cmd = server.command || '';
  let args = [...server.args];
  // `command` may contain the whole line (some clients allow it).
  // Some clients accept the whole command line in `command`. Split it unless it
  // looks like a path that happens to contain spaces.
  if (cmd.includes(' ') && args.length === 0 && !/[\\/]/.test(cmd)) {
    const parts = cmd.split(/\s+/);
    cmd = parts.shift();
    args = parts;
  }
  for (let guard = 0; guard < 3; guard++) {
    const b = baseCommand(cmd);
    if (b === 'cmd' && /^\/c$/i.test(args[0] || '')) { cmd = args[1] || ''; args = args.slice(2); continue; }
    if (b === 'wsl' && args.length) { cmd = args[0]; args = args.slice(1); continue; }
    if (b === 'env' && args.length) {
      while (args.length && /^[A-Za-z_]\w*=/.test(args[0])) args.shift();
      cmd = args.shift() || ''; continue;
    }
    break;
  }
  return { cmd, base: baseCommand(cmd), args };
}

function npmSpec(spec) {
  const r = { spec, manager: 'npm', name: spec, version: null, kind: 'registry', pinned: false };
  if (/^(\.|\/|~|file:)/.test(spec) || /^[A-Za-z]:[\\/]/.test(spec)) { r.kind = 'local'; r.pinned = true; return r; }
  if (/^(github:|gitlab:|bitbucket:|git\+|git:\/\/)/.test(spec) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec)) {
    r.kind = 'git';
    const ref = spec.split('#')[1];
    r.version = ref || null;
    r.pinned = !!ref && COMMIT.test(ref);
    return r;
  }
  if (/^https?:\/\//.test(spec)) { r.kind = 'url'; r.pinned = false; return r; }
  const at = spec.lastIndexOf('@');
  if (at > 0) { r.name = spec.slice(0, at); r.version = spec.slice(at + 1); }
  r.pinned = !!r.version && SEMVER.test(r.version);
  return r;
}

function pySpec(spec) {
  const r = { spec, manager: 'pypi', name: spec, version: null, kind: 'registry', pinned: false };
  if (/^git\+/.test(spec) || /^https?:\/\//.test(spec)) {
    r.kind = /^git\+/.test(spec) ? 'git' : 'url';
    const m = spec.match(/@([0-9a-f]{40})(#|$)/i);
    r.pinned = !!m;
    r.name = spec.replace(/^.*\//, '').replace(/(\.git)?(@.*)?$/, '');
    return r;
  }
  if (/^(\.|\/|~)/.test(spec)) { r.kind = 'local'; r.pinned = true; return r; }
  let m = spec.match(/^([A-Za-z0-9_.\-[\],]+?)\s*==\s*([^,;\s]+)$/);
  if (m) { r.name = m[1]; r.version = m[2]; r.pinned = PY_EXACT.test(m[2]); return r; }
  m = spec.match(/^([A-Za-z0-9_.\-[\],]+?)@([^@\s]+)$/);
  if (m) { r.name = m[1]; r.version = m[2]; r.pinned = PY_EXACT.test(m[2]); return r; }
  m = spec.match(/^([A-Za-z0-9_.\-[\],]+?)\s*(>=|<=|~=|>|<|!=)/);
  if (m) { r.name = m[1]; r.version = spec.slice(m[1].length); r.pinned = false; }
  r.name = r.name.replace(/\[.*\]$/, '');
  return r;
}

const DOCKER_VALUE_FLAGS = new Set(['-e', '--env', '-v', '--volume', '--name', '--network', '--net', '-p', '--publish', '--mount', '--env-file', '-w', '--workdir', '--entrypoint', '--user', '-u', '--cap-add', '--cap-drop', '--pid', '--platform', '--label', '-l', '--add-host', '--device', '--memory', '-m', '--cpus', '--hostname', '-h', '--security-opt', '--ipc', '--userns', '--tmpfs', '--ulimit', '--restart', '--pull', '--gpus', '--uts']);

export function parseDockerRun(args) {
  const i0 = args.findIndex((a) => a === 'run');
  if (i0 < 0) return null;
  const flags = [];
  let image = null;
  for (let i = i0 + 1; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('-')) {
      if (a.includes('=')) { flags.push([a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)]); continue; }
      if (DOCKER_VALUE_FLAGS.has(a)) { flags.push([a, args[i + 1] ?? '']); i++; continue; }
      flags.push([a, true]);
      continue;
    }
    image = a;
    break;
  }
  return { image, flags };
}

export function dockerImageRef(image) {
  const r = { spec: image, manager: 'docker', name: image, version: null, kind: 'image', pinned: false, digest: false };
  if (!image) return r;
  if (image.includes('@sha256:')) { r.digest = true; r.pinned = true; r.name = image.split('@')[0]; return r; }
  const lastSlash = image.lastIndexOf('/');
  const colon = image.lastIndexOf(':');
  if (colon > lastSlash) { r.name = image.slice(0, colon); r.version = image.slice(colon + 1); }
  r.pinned = !!r.version && r.version !== 'latest';
  return r;
}

// Returns the packages a server definition launches (usually zero or one).
export function launchedPackages(server) {
  const { base, args } = effectiveCommand(server);
  const out = [];
  const positional = (list, valueFlags) => {
    for (let i = 0; i < list.length; i++) {
      const a = list[i];
      if (a === '--') return list[i + 1] ?? null;
      if (a.startsWith('-')) { if (valueFlags.includes(a)) i++; continue; }
      return a;
    }
    return null;
  };

  if (['npx', 'bunx', 'npm', 'pnpm', 'yarn', 'bun'].includes(base)) {
    let rest = args;
    if (base === 'npm' && args[0] === 'exec') rest = args.slice(1);
    else if (['pnpm', 'yarn'].includes(base) && args[0] === 'dlx') rest = args.slice(1);
    else if (base === 'bun' && args[0] === 'x') rest = args.slice(1);
    else if (!['npx', 'bunx'].includes(base)) return out;
    const pkgFlag = rest.findIndex((a) => a === '-p' || a === '--package');
    const eq = rest.find((a) => a.startsWith('--package='));
    const spec = eq ? eq.slice(10) : pkgFlag >= 0 ? rest[pkgFlag + 1] : positional(rest, ['-p', '--package', '-c', '--call', '--registry', '--cache', '--userconfig']);
    if (spec) out.push(npmSpec(spec));
  } else if (base === 'uvx' || (base === 'uv' && args[0] === 'tool' && args[1] === 'run')) {
    const rest = base === 'uv' ? args.slice(2) : args;
    const fromIdx = rest.findIndex((a) => a === '--from');
    const eq = rest.find((a) => a.startsWith('--from='));
    const spec = eq ? eq.slice(7) : fromIdx >= 0 ? rest[fromIdx + 1] : positional(rest, ['--with', '--python', '-p', '--index', '--index-url', '--extra-index-url', '--from']);
    if (spec) out.push(pySpec(spec));
  } else if (base === 'pipx' && args[0] === 'run') {
    const rest = args.slice(1);
    const sIdx = rest.findIndex((a) => a === '--spec');
    const spec = sIdx >= 0 ? rest[sIdx + 1] : positional(rest, ['--spec', '--python', '--index-url']);
    if (spec) out.push(pySpec(spec));
  } else if (['docker', 'podman'].includes(base)) {
    const d = parseDockerRun(args);
    if (d && d.image) out.push(dockerImageRef(d.image));
  }
  return out;
}

// Positional arguments that come after the package spec (e.g. filesystem roots).
export function argsAfterPackage(server) {
  const { args } = effectiveCommand(server);
  const pkgs = launchedPackages(server);
  if (!pkgs.length) return args.filter((a) => !a.startsWith('-'));
  const idx = args.indexOf(pkgs[0].spec);
  return idx >= 0 ? args.slice(idx + 1).filter((a) => !a.startsWith('-')) : [];
}
