// Works out which package (npm, PyPI, Docker image) a server launches, and
// whether that reference is pinned to an exact version.
import path from 'node:path';

const SEMVER = /^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/;
const PY_EXACT = /^\d+(\.\d+)*([a-z]+\d*)?(\.post\d+)?(\.dev\d+)?$/i;
const COMMIT = /^[0-9a-f]{40}$/i;

export function baseCommand(cmd) {
  if (!cmd || typeof cmd !== 'string') return '';
  return path.basename(cmd.replace(/\\/g, '/')).toLowerCase().replace(/\.(cmd|exe|bat|ps1)$/, '');
}

// Split a command line the way a POSIX shell would: whitespace separates
// words, and single and double quotes group them. Outside quotes a backslash
// only escapes whitespace or a quote, so Windows paths keep their backslashes.
export function splitCommandLine(line) {
  return splitCommandLineSpans(line).map((w) => w.text);
}

/**
 * splitCommandLine() with the place of each word in the line: `start` and
 * `end` cover the word as written, quotes and backslashes included.
 * @returns {{text: string, start: number, end: number}[]}
 */
export function splitCommandLineSpans(line) {
  const out = [];
  const str = String(line ?? '');
  let cur = '';
  let word = false;
  let start = 0;
  let quote = null;
  const begin = (i) => { if (!word) { word = true; start = i; } };
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (quote === "'") { if (c === "'") quote = null; else cur += c; continue; }
    if (quote === '"') {
      if (c === '"') quote = null;
      else if (c === '\\' && /["\\$`]/.test(str[i + 1] || '')) cur += str[++i];
      else cur += c;
      continue;
    }
    if (c === "'" || c === '"') { begin(i); quote = c; continue; }
    if (c === '\\' && /[\s"']/.test(str[i + 1] || '')) { begin(i); cur += str[++i]; continue; }
    if (/\s/.test(c)) { if (word) out.push({ text: cur, start, end: i }); cur = ''; word = false; continue; }
    begin(i);
    cur += c;
  }
  if (word) out.push({ text: cur, start, end: str.length });
  return out;
}

// Programs that commonly start a whole command line written into `command`.
const LAUNCHERS = new Set(['npx', 'bunx', 'npm', 'pnpm', 'yarn', 'bun', 'uvx', 'uv', 'pipx', 'docker', 'podman', 'node', 'nodejs',
  'python', 'python3', 'py', 'deno', 'tsx', 'ts-node', 'cmd', 'wsl', 'env', 'sh', 'bash', 'zsh', 'pwsh', 'powershell', 'java']);

// Unwrap `cmd /c npx ...` and `wsl npx ...` style launchers.
export function effectiveCommand(server) {
  // JSON can hold anything here; only a string command and string arguments are used.
  let cmd = typeof server?.command === 'string' ? server.command : '';
  let args = Array.isArray(server?.args) ? server.args.map(String) : [];
  // Some clients accept the whole command line in `command`. Split it like a
  // shell would, unless it looks like a path that happens to contain spaces:
  // a slash somewhere and a first word that is not a known launcher.
  if (args.length === 0 && /\s/.test(cmd.trim())) {
    const parts = splitCommandLine(cmd.trim());
    if (parts.length > 1 && (!/[\\/]/.test(cmd) || LAUNCHERS.has(baseCommand(parts[0])))) {
      cmd = parts[0];
      args = parts.slice(1);
    }
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

// `docker run` / `podman run` options that take the next argument as their
// value. Anything not listed is read as a boolean flag, so a missing entry
// makes the parser take the flag's value for the image and stop early.
const DOCKER_VALUE_FLAGS = new Set([
  '-a', '--attach', '-c', '--cpu-shares', '-e', '--env', '-h', '--hostname', '-l', '--label', '-m', '--memory', '-p', '--publish',
  '-u', '--user', '-v', '--volume', '-w', '--workdir',
  '--add-host', '--annotation', '--blkio-weight', '--blkio-weight-device', '--cap-add', '--cap-drop', '--cgroup-parent', '--cgroupns',
  '--cidfile', '--cpu-count', '--cpu-percent', '--cpu-period', '--cpu-quota', '--cpu-rt-period', '--cpu-rt-runtime', '--cpus',
  '--cpuset-cpus', '--cpuset-mems', '--detach-keys', '--device', '--device-cgroup-rule', '--device-read-bps', '--device-read-iops',
  '--device-write-bps', '--device-write-iops', '--dns', '--dns-opt', '--dns-option', '--dns-search', '--domainname', '--entrypoint',
  '--env-file', '--expose', '--gpus', '--group-add', '--health-cmd', '--health-interval', '--health-retries', '--health-start-interval',
  '--health-start-period', '--health-timeout', '--io-maxbandwidth', '--io-maxiops', '--ip', '--ip6', '--ipc', '--isolation',
  '--kernel-memory', '--label-file', '--link', '--link-local-ip', '--log-driver', '--log-opt', '--mac-address', '--memory-reservation',
  '--memory-swap', '--memory-swappiness', '--mount', '--name', '--net', '--net-alias', '--network', '--network-alias', '--oom-score-adj',
  '--pid', '--pids-limit', '--platform', '--pull', '--restart', '--runtime', '--security-opt', '--shm-size', '--stop-signal',
  '--stop-timeout', '--storage-opt', '--sysctl', '--tmpfs', '--ulimit', '--userns', '--uts', '--volume-driver', '--volumes-from',
  // podman only
  '--arch', '--cgroup-conf', '--cgroups', '--chrootdirs', '--conmon-pidfile', '--decryption-key', '--gidmap', '--group-entry',
  '--hooks-dir', '--init-path', '--os', '--passwd-entry', '--personality', '--pidfile', '--pod', '--pod-id-file', '--preserve-fds',
  '--rdt-class', '--requires', '--retry', '--retry-delay', '--sdnotify', '--seccomp-policy', '--secret', '--subgidname',
  '--subuidname', '--timeout', '--tz', '--uidmap', '--umask', '--unsetenv', '--variant',
  '--authfile', '--cert-dir', '--creds', '--env-merge', '--health-log-destination', '--health-max-log-count', '--health-max-log-size',
  '--health-on-failure', '--health-startup-cmd', '--health-startup-interval', '--health-startup-retries', '--health-startup-success',
  '--health-startup-timeout', '--hostuser', '--hosts-file', '--image-volume', '--preserve-fd', '--shm-size-systemd', '--signature-policy',
  '--systemd',
]);

// Single-letter flags that take a value, for the combined (-itv /:/host) and
// attached (-v/:/host) short forms.
const DOCKER_SHORT_VALUE = new Set(['a', 'c', 'e', 'h', 'l', 'm', 'p', 'u', 'v', 'w']);
const DOCKER_SHORT_BOOL = new Set(['i', 't', 'd', 'q', 'P']);

// What an image reference can look like: [host[:port]/]path[:tag][@digest].
// A path, a key=value pair or a word with characters an image cannot hold
// is the value of an option this parser does not know.
const IMAGE_REF = /^[A-Za-z0-9][A-Za-z0-9._-]*(?::\d+)?(?:\/[A-Za-z0-9._-]+)*(?::[\w][\w.-]*)?(?:@[A-Za-z0-9]+:[A-Fa-f0-9]+)?$/;

export function parseDockerRun(args) {
  const list = (Array.isArray(args) ? args : []).map(String);
  const i0 = list.findIndex((a) => a === 'run');
  if (i0 < 0) return null;
  const flags = [];
  let image = null;
  let unknownLong = false;
  for (let i = i0 + 1; i < list.length; i++) {
    const a = list[i];
    if (a.startsWith('-') && a.length > 1) {
      unknownLong = false;
      if (DOCKER_VALUE_FLAGS.has(a)) { flags.push([a, list[i + 1] ?? '']); i++; continue; }
      if (!a.startsWith('--')) {
        // -it, -itv /:/host, -v/:/host, -eFOO=bar: boolean letters, then at most one letter with a value.
        let k = 1;
        while (k < a.length && DOCKER_SHORT_BOOL.has(a[k])) { flags.push([`-${a[k]}`, true]); k++; }
        if (k === a.length) continue;
        if (DOCKER_SHORT_VALUE.has(a[k])) {
          const rest = a.slice(k + 1).replace(/^=/, '');
          if (rest) flags.push([`-${a[k]}`, rest]);
          else { flags.push([`-${a[k]}`, list[i + 1] ?? '']); i++; }
          continue;
        }
        flags.push([a, true]); // an unknown short option
        continue;
      }
      if (a.includes('=')) { flags.push([a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)]); continue; }
      flags.push([a, true]);
      unknownLong = true;
      continue;
    }
    // The value of an unknown option, such as a podman flag missing from the list above.
    if (unknownLong && !IMAGE_REF.test(a)) { flags[flags.length - 1][1] = a; unknownLong = false; continue; }
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
