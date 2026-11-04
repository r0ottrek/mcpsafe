# mcpsafe

mcpsafe reads the MCP server configuration of the AI tools on your machine (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline, Roo Code and Gemini CLI) and reports setups that are likely to hurt you: credentials stored in plain text, packages that run whatever version was published last, servers with shell or whole-disk access, tools that run without asking, and tool descriptions carrying hidden instructions for the model.

```
npx github:r0ottrek/mcpsafe
```

It needs Node 18 or later and has no dependencies. npx fetches it straight from this repository, so there is nothing to install. A normal scan only reads files.

To keep it around as a `mcpsafe` command, install it once with `npm install -g github:r0ottrek/mcpsafe`. The examples below use that short name.

## Example

Each finding points at the file and line it came from. Credentials are masked.

```
high[MCS001]: Secret stored in plain text
  --> ~/Library/Application Support/Claude/claude_desktop_config.json:10
   |
10 |         "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_••••••••"
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   = note: GitHub token found in env.GITHUB_PERSONAL_ACCESS_TOKEN.
   = server: github (Claude Desktop)
   = fix: Move the value into your OS keychain or a shell environment variable and reference it
          from the config (for example "${env:GITHUB_TOKEN}" in VS Code, or an env var exported
          before launching the client). Rotate the exposed key.

high[MCS005]: Remote server uses unencrypted HTTP
  --> ~/.cursor/mcp.json:14
   |
14 |       "url": "http://weather-tools.dev/mcp"
   |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Connects to weather-tools.dev over plain http.
   = server: weather (Cursor)
   = fix: Use an https:// endpoint. Plain http is only acceptable for localhost.
```

After the findings comes a score out of 100 and the fixes ordered by how much each one improves it:

```
score: 36/100 (F), 9 findings: 5 high, 4 medium

fix first:
   +7  Secret stored in plain text                     github
   +7  Remote server uses unencrypted HTTP             weather
   +7  Server can run arbitrary shell commands         commander
   +7  Filesystem access is too broad                  filesystem
   +7  Package name looks like a typosquat             memory
   +2  Config with secrets is readable by other users  claude_desktop_config.json
   +2  Package version is not pinned                   github
   +2  Tools are auto-approved                         commander
   +2  Project MCP servers are enabled automatically   settings.json
```

<img src="docs/demo.gif" width="760" alt="Terminal recording of npx mcpsafe scanning a machine with Claude Desktop, Claude Code and Cursor configured">

## HTML report

`mcpsafe --html` writes the same results to one self-contained HTML file that can be read offline, sent to someone, or printed. It lists the fixes in order, every server and what it runs, and each finding with the lines of config involved. Findings can be filtered by severity or server.

<img src="docs/report.png" width="760" alt="First page of the HTML report: score 24 of 100, grade F, a 0 to 100 scale with grade bands, and the table of fixes">

## Checking tool descriptions

A server's tool descriptions are passed to the model verbatim, and you normally never read them. A malicious or compromised server can use them to tell the model to read `~/.ssh/id_rsa` and pass it along as a harmless-looking parameter. With `--connect`, mcpsafe starts each configured server, lists its tools over MCP (stdio or Streamable HTTP) and checks every tool and parameter description. The HTML report highlights the phrases that matched:

<img src="docs/finding.png" width="760" alt="A critical finding in the HTML report: the get_forecast tool description with its hidden instruction to read ~/.ssh/id_rsa highlighted">

`--connect` runs the servers, so use it only where that is acceptable. To check a saved `tools/list` response instead, pass it with `--tools file.json`.

## Checks

| ID | Default severity | What it looks for |
|---|---|---|
| MCS001 | high, critical in repository files | API keys, tokens, `Authorization` headers and database passwords written into a config |
| MCS002 | medium | A config holding secrets that other users on the machine can read |
| MCS003 | medium | `npx`, `uvx` or `pipx` packages without an exact version |
| MCS004 | medium | Docker images with no tag or `:latest` |
| MCS005 | high | Remote servers on plain `http://` (localhost is fine) |
| MCS006 | high | Tokens in a server URL's query string |
| MCS007 | high | Servers that offer shell or command execution |
| MCS008 | high | Filesystem access to `/`, `~`, `C:\` or a whole home directory, including Docker mounts |
| MCS009 | high | Containers run with `--privileged`, host networking or PID namespace, extra capabilities, or the Docker socket |
| MCS010 | critical | A launch command that pipes a downloaded script into a shell |
| MCS011 | medium or high | Auto-approval: `autoApprove`, `alwaysAllow`, `trust: true`, broad `mcp__` allow rules, `bypassPermissions`, `chat.tools.autoApprove` |
| MCS012 | medium | Claude Code's `enableAllProjectMcpServers`, which lets any cloned repository start servers |
| MCS013 | high | Package names one or two characters away from a popular MCP server |
| MCS014 | medium | Servers run from `/tmp`, `Downloads` or another temporary folder |
| MCS015 | high | Invisible Unicode (zero-width, bidirectional override, tag characters) in a config |
| MCS016 | critical | Hidden instructions in tool or parameter descriptions (needs `--connect` or `--tools`) |
| MCS017 | medium | Two servers exposing the same tool name, or one server's descriptions giving orders about another's tools |
| MCS018 | medium | Packages installed from a git branch or URL instead of a pinned release |

`mcpsafe --rules` prints this list. The explanation and fix for each rule are in [src/rules.js](src/rules.js).

## Where it looks

| Client | Files |
|---|---|
| Claude Desktop | `claude_desktop_config.json` in the app's config folder on macOS, Windows and Linux |
| Claude Code | `~/.claude.json`, `~/.claude/settings.json`, and in projects `.mcp.json` and `.claude/settings*.json` |
| Cursor | `~/.cursor/mcp.json`, `.cursor/mcp.json` |
| VS Code | the user `mcp.json` and `settings.json`, `.vscode/mcp.json`, `.vscode/settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Cline, Roo Code | their MCP settings files under VS Code's `globalStorage`, and `.roo/mcp.json` |
| Gemini CLI | `~/.gemini/settings.json`, `.gemini/settings.json` |

With no arguments mcpsafe scans these files in your home directory and the project files in the current folder itself, without descending into subfolders. Any other file or folder can be passed as an argument; folders passed this way are searched recursively for the project files above. JSON with comments and trailing commas is accepted.

## Options

```
mcpsafe [paths...] [options]

  --no-home             only scan the given paths, not your home directory
  --html [file]         write an HTML report (default mcpsafe-report.html)
  --connect             start each server and check its tool descriptions
  --tools <file>        check tool descriptions from a saved tools/list response
  --json                print JSON instead of the text report
  --sarif <file>        write SARIF 2.1.0 for GitHub code scanning
  --markdown <file>     append a Markdown summary, e.g. to $GITHUB_STEP_SUMMARY
  --fail-on <severity>  exit 1 if a finding is at or above critical, high, medium or low
  --min-score <n>       exit 1 if the score is below n
  --ignore <ids>        skip rules, e.g. --ignore MCS003,MCS004
  -v, --verbose         also list the files that were scanned
  --rules               list the rules
```

## GitHub Action

The action scans the MCP configs committed to a repository. Findings appear as annotations on the changed lines of a pull request and as a table in the job summary.

```yaml
on: [push, pull_request]

jobs:
  mcpsafe:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only needed for the SARIF upload
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

Inputs are `path` (default `.`), `fail-on` (default `high`, or `none`), `min-score`, `ignore`, `sarif` (default `mcpsafe.sarif`) and `html`. Outputs are `score`, `grade`, `findings` and `sarif`.

## Scoring

Each finding costs points by severity: 25 for critical, 12 for high, 4 for medium and 1.5 for low. A second finding from the same rule costs half as much, a third a quarter, and further ones nothing, so one repeated problem cannot dominate. The total is converted to a score with `100 × e^(−points/75)`, then to a grade: A from 90, B from 80, C from 70, D from 60, F below. Two unpinned packages leave you at 92; a token in a config plus a shell server puts you at 73.

The score is for deciding what to fix first. It does not show that a setup is safe: mcpsafe reads configuration and cannot judge the code a server runs.

## Library use

```js
import { scan } from 'mcpsafe';

const result = await scan({ paths: ['.'], includeHome: false });
console.log(result.score.value, result.findings.length);
```

## Development

```
git clone https://github.com/r0ottrek/mcpsafe
cd mcpsafe
npm test
npm run demo
```

`examples/risky-setup` triggers most rules and `examples/safe-setup` scores 100. The credentials in the examples are fake. `scripts/demo` rebuilds the GIF and screenshots in `docs/`.

## License

MIT
