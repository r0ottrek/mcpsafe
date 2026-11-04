// Rule catalog. Each rule has a stable ID, a default severity, and fix advice.
// The logic that triggers each rule lives in checks.js.
//
// Some rules report findings at more than one severity. Their `range` gives
// the lowest and highest severity a finding can have, so that --rules and the
// README can say "low to high" instead of only the default. `severity` stays
// the default, which SARIF rule descriptors use. A finding on a disabled
// server is one step lower than usual; the range leaves that out.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export const RULES = {
  MCS001: {
    title: 'Secret stored in plain text',
    severity: 'high',
    range: ['medium', 'critical'],
    why: 'API keys and tokens pasted into MCP config files end up in backups, dotfile repos, screen shares and support bundles. Any process running as you can read them.',
    fix: 'Move the value into your OS keychain or a shell environment variable and reference it from the config (for example "${env:GITHUB_TOKEN}" in VS Code, or an env var exported before launching the client). Rotate the exposed key.',
  },
  MCS002: {
    title: 'Config with secrets is readable by other users',
    severity: 'medium',
    why: 'The file contains credentials and its permissions let other accounts on this machine read it.',
    fix: 'Restrict the file to your user: chmod 600 <file>.',
  },
  MCS003: {
    title: 'Package version is not pinned',
    severity: 'medium',
    why: 'npx / uvx fetch whatever version is newest every time the client starts. A compromised or hijacked release runs on your machine automatically, with no review.',
    fix: 'Pin an exact version, e.g. "@playwright/mcp@0.0.84" for npx or "mcp-server-fetch==2026.10.28" for uvx, and upgrade deliberately.',
  },
  MCS004: {
    title: 'Container image is not pinned',
    severity: 'medium',
    why: 'An image without a tag, or tagged :latest, can change under you. Tags are also mutable, so a digest is the only true pin.',
    fix: 'Reference the image by digest (image@sha256:...) or at least an explicit version tag.',
  },
  MCS005: {
    title: 'Remote server uses unencrypted HTTP',
    severity: 'high',
    why: 'Tool calls, results and any auth headers travel in clear text and can be read or modified on the network.',
    fix: 'Use an https:// endpoint. Plain http is only acceptable for localhost.',
  },
  MCS006: {
    title: 'Credential embedded in server URL',
    severity: 'high',
    why: 'Tokens in query strings get written to proxy logs, server logs and browser history.',
    fix: 'Send the credential in an Authorization header sourced from an environment variable or use the server\'s OAuth flow.',
  },
  MCS007: {
    title: 'Server can run arbitrary shell commands',
    severity: 'high',
    range: ['low', 'high'],
    why: 'A shell or terminal tool lets the model (or a prompt injection in any document it reads) run any command as you.',
    fix: 'Remove it if you do not need it. Otherwise keep every call behind manual approval, never auto-approve it, and run it inside a container or VM with no access to your home directory.',
  },
  MCS008: {
    title: 'Filesystem access is too broad',
    severity: 'high',
    why: 'The server can read and write your whole disk or home directory, including SSH keys, browser profiles, cloud credentials and other MCP configs.',
    fix: 'Limit the allowed directories to the specific project folders the agent needs.',
  },
  MCS009: {
    title: 'Container runs with dangerous privileges',
    severity: 'high',
    why: 'Privileged mode, host networking, the Docker socket or host-root mounts let code in the container escape to the host.',
    fix: 'Drop --privileged, --network host, --pid host and extra capabilities, and do not mount /var/run/docker.sock or the host root.',
  },
  MCS010: {
    title: 'Downloads and runs a remote script',
    severity: 'critical',
    why: 'The launch command pipes a script from the internet straight into a shell. Whoever controls that URL controls your machine on every start.',
    fix: 'Download the script once, review it, and run a local pinned copy, or install the server from a package registry with a pinned version.',
  },
  MCS011: {
    title: 'Tools are auto-approved',
    severity: 'medium',
    range: ['medium', 'high'],
    why: 'Auto-approval removes the human check between the model deciding to call a tool and the tool running. Prompt injection then goes straight to action.',
    fix: 'Remove auto-approve / alwaysAllow / trust entries, or limit them to read-only tools you have reviewed.',
  },
  MCS012: {
    title: 'Project MCP servers are enabled automatically',
    severity: 'medium',
    why: 'Any repository you clone can ship an .mcp.json that starts servers on your machine without asking.',
    fix: 'Set "enableAllProjectMcpServers" to false and approve project servers one by one.',
  },
  MCS013: {
    title: 'Package name looks like a typosquat',
    severity: 'high',
    range: ['medium', 'high'],
    why: 'The package name is one or two characters away from a popular MCP server. Lookalike packages are a common supply-chain attack.',
    fix: 'Check the exact package name and publisher on the registry before running it.',
  },
  MCS014: {
    title: 'Server runs from a temporary or download folder',
    severity: 'medium',
    why: 'Files in /tmp or Downloads can be replaced by other processes or by anything you download.',
    fix: 'Install the server into a stable location owned by you, or use a pinned package.',
  },
  MCS015: {
    title: 'Hidden Unicode characters in config',
    severity: 'high',
    why: 'Zero-width, bidirectional-override and tag characters can hide text from you while the model or shell still reads it.',
    fix: 'Open the file in an editor that reveals invisible characters and remove them.',
  },
  MCS016: {
    title: 'Hidden instructions in tool description',
    severity: 'critical',
    range: ['low', 'critical'],
    why: 'Tool descriptions go straight into the model\'s context. Instructions hidden there (tool poisoning) can make the agent read secrets or exfiltrate data without you seeing it.',
    fix: 'Remove the server and report it to the maintainer. Pin a version you have reviewed.',
  },
  MCS017: {
    title: 'Tool shadows or references another server\'s tools',
    severity: 'medium',
    range: ['low', 'high'],
    why: 'Two servers exposing the same tool name, or one server\'s description giving orders about another server\'s tools, is how cross-server tool hijacking works.',
    fix: 'Remove one of the conflicting servers, or confirm both are trusted and rename/prefix tools if your client supports it.',
  },
  MCS018: {
    title: 'Installed from git or URL instead of a registry',
    severity: 'medium',
    why: 'Git branches and raw URLs are not versioned releases. The code can change at any time and bypasses registry malware scanning.',
    fix: 'Install from the registry with a pinned version, or pin the git reference to a full commit SHA.',
  },
};

// The severity of a rule for display: its range ("low to high") when its
// findings vary, else its one severity.
export function severityLabel(rule) {
  return rule.range ? `${rule.range[0]} to ${rule.range[1]}` : rule.severity;
}

export function ruleList() {
  return Object.entries(RULES).map(([id, r]) => ({ id, ...r, severityLabel: severityLabel(r) }));
}
