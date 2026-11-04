# mcpsafe

A security audit for the MCP servers your AI tools run. One command, nothing to install.

```
npx github:r0ottrek/mcpsafe
```

<img src="docs/terminal.png" width="793" alt="mcpsafe in a terminal: an ASCII logo, a score of 36 out of 100 with grade F, a severity chart, findings grouped by server with their config line numbers, and a list of fixes ordered by how many points each one is worth">

mcpsafe reads the MCP configuration of Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline, Roo Code and Gemini CLI, and reports:

- credentials written into a config in plain text
- packages that run whatever version was published last
- servers with shell access, or access to your whole disk
- tools that run without asking you first
- tool descriptions carrying hidden instructions for the model

It needs Node 18 or later and has no dependencies. A normal scan only reads files.

## Usage

```sh
mcpsafe                      # your user configs, plus the project in the current folder
mcpsafe -v                   # show each finding in its config file, with the fix
mcpsafe --html               # write mcpsafe-report.html
mcpsafe ~/code               # search a folder of projects
mcpsafe --connect            # also start each server and check its tool descriptions
```

The examples use the short name. Install it once with `npm install -g github:r0ottrek/mcpsafe`, or put `npx github:r0ottrek/mcpsafe` in front of the options instead.

## Reports

`--html` writes one self-contained file that opens offline, prints cleanly and can be sent to someone. It has the fixes in order, every server and what it runs, and each finding with the lines of config involved.

<img src="docs/report.png" width="760" alt="First page of the HTML report: score 24 of 100, grade F, a 0 to 100 scale with grade bands, and the table of fixes">

`--sarif` writes SARIF 2.1.0 for GitHub code scanning, `--markdown` appends a summary for a CI job page, and `--json` prints everything as JSON.

## Hidden instructions in tool descriptions

A server's tool descriptions go to the model verbatim, and you normally never read them. A malicious or compromised server can use them to tell the model to read `~/.ssh/id_rsa` and pass it along as a harmless-looking parameter.

With `--connect`, mcpsafe starts each configured server, lists its tools over MCP (stdio or Streamable HTTP) and checks every tool and parameter description. Because that runs the servers, use it only where that is acceptable. To check a saved `tools/list` response instead, pass it with `--tools file.json`.

<img src="docs/finding.png" width="760" alt="A critical finding in the HTML report: the get_forecast tool description with its hidden instruction to read ~/.ssh/id_rsa highlighted">

## Checks

| ID | Severity | Finds |
|---|---|---|
| MCS001 | high | API keys, tokens, `Authorization` headers and database passwords in a config (critical in a repository) |
| MCS002 | medium | A config holding secrets that other users on the machine can read |
| MCS003 | medium | `npx`, `uvx` or `pipx` packages without an exact version |
| MCS004 | medium | Docker images with no tag or `:latest` |
| MCS005 | high | Remote servers on plain `http://` (localhost is fine) |
| MCS006 | high | Tokens in a server URL's query string |
| MCS007 | high | Servers that offer shell or command execution |
| MCS008 | high | Filesystem access to `/`, `~`, `C:\` or a whole home directory, including Docker mounts |
| MCS009 | high | Containers with `--privileged`, host networking or PID namespace, extra capabilities, or the Docker socket |
| MCS010 | critical | A launch command that pipes a downloaded script into a shell |
| MCS011 | medium | Auto-approval: `autoApprove`, `alwaysAllow`, `trust: true`, broad `mcp__` allow rules, `bypassPermissions` |
| MCS012 | medium | Claude Code's `enableAllProjectMcpServers`, which lets any cloned repository start servers |
| MCS013 | high | Package names one or two characters away from a popular MCP server |
| MCS014 | medium | Servers run from `/tmp`, `Downloads` or another temporary folder |
| MCS015 | high | Invisible Unicode (zero-width, bidirectional override, tag characters) in a config |
| MCS016 | critical | Hidden instructions in tool or parameter descriptions (needs `--connect` or `--tools`) |
| MCS017 | medium | Two servers exposing the same tool name, or one server giving orders about another's tools |
| MCS018 | medium | Packages installed from a git branch or URL instead of a pinned release |

The reasoning and the fix for each rule are in [src/rules.js](src/rules.js). `mcpsafe --rules` lists them.

## Where it looks

| Client | Files |
|---|---|
| Claude Desktop | `claude_desktop_config.json` in the app's config folder on macOS, Windows and Linux, including the Microsoft Store install under `AppData\Local\Packages\Claude_*` |
| Claude Code | `~/.claude.json`, `~/.claude/settings.json`, and in projects `.mcp.json` and `.claude/settings*.json` |
| Cursor | `~/.cursor/mcp.json`, `.cursor/mcp.json` |
| VS Code | the user `mcp.json` and `settings.json` and those of each profile, `.vscode/mcp.json`, `.vscode/settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Cline, Roo Code | their settings files under the `globalStorage` of VS Code, Cursor and Windsurf, and `.roo/mcp.json` |
| Gemini CLI | `~/.gemini/settings.json`, `~/.gemini/extensions/*/gemini-extension.json`, `.gemini/settings.json` |

With no arguments it scans these files in your home directory and the project files in the current folder, without descending into subfolders. A folder passed as an argument is searched recursively. JSON with comments and trailing commas is fine.

## In CI

The action scans the MCP configs committed to a repository. Findings show up as annotations on the pull request and as a table in the job summary.

```yaml
on: [push, pull_request]

jobs:
  mcpsafe:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only for the SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: r0ottrek/mcpsafe@v1
        with:
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcpsafe.sarif
```

Inputs: `path` (default `.`), `fail-on` (default `high`, or `none`), `min-score`, `ignore`, `sarif` (default `mcpsafe.sarif`) and `html`. Outputs: `score`, `grade`, `findings` and `sarif`.

Outside the action, `--fail-on <severity>` and `--min-score <n>` set the exit code, and `--ignore MCS003,MCS004` skips rules.

## Scoring

Each finding costs points by severity: 25 for critical, 12 for high, 4 for medium and 1.5 for low. A second finding from the same rule costs half as much, a third a quarter, and further ones nothing, so one repeated problem cannot dominate. The score is `100 × e^(−points/75)`, graded A from 90, B from 80, C from 70, D from 60 and F below. Two unpinned packages leave you at 92; a token in a config plus a shell server puts you at 73.

The score tells you what to fix first. It does not show that a setup is safe: mcpsafe reads configuration and cannot judge the code a server runs.

## As a library

```js
import { scan } from 'mcpsafe';

const result = await scan({ paths: ['.'], includeHome: false });
console.log(result.score.value, result.findings.length);
```

## Development

```sh
git clone https://github.com/r0ottrek/mcpsafe
cd mcpsafe
npm test
npm run demo
```

`examples/risky-setup` triggers most rules and `examples/safe-setup` scores 100. Credentials in the examples are fake. The images in `docs/` are rebuilt by the scripts in `scripts/demo`.

## License

MIT
