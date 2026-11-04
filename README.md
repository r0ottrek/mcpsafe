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
mcpsafe ~/.cursor            # a client's config folder works too
mcpsafe --no-home            # only the project in the current folder
mcpsafe --connect            # also start each server and check its tool descriptions
```

The examples use the short name. Install it once with `npm install -g github:r0ottrek/mcpsafe`, or put `npx github:r0ottrek/mcpsafe` in front of the options instead.

### Options

| Option | Does |
|---|---|
| `--no-home` | Skip user-level configs; scan only the given paths, or the current folder if none are given |
| `--home <dir>` | Treat `<dir>` as the home directory. It must be an existing folder |
| `--connect` | Start each server and check its tool descriptions (runs the servers) |
| `--tools <file>` | Check tool descriptions from a saved file; can be repeated |
| `--html [file.html]` | Write an HTML report, `mcpsafe-report.html` by default. The next argument is taken as the file name only if it ends in `.html` or `.htm`, so `mcpsafe --html .mcp.json` scans `.mcp.json`. Use `--html=<file>` for any other name; an existing file of another name is replaced only if it is an earlier mcpsafe report |
| `--sarif <file>` | Write SARIF 2.1.0 |
| `--markdown <file>` | Append a Markdown summary |
| `--json` | Print results as JSON |
| `--fail-on <severity>` | Exit 1 if a finding is at or above `critical`, `high`, `medium` or `low` |
| `--min-score <n>` | Exit 1 if the score is below `n`, a number from 0 to 100 |
| `--ignore <ids>` | Skip rules, e.g. `MCS003,MCS004`; can be repeated. An unknown rule ID gets a warning |
| `-v`, `--verbose` | Show each finding in its config file, with the fix |
| `--no-color` | Disable colors. `NO_COLOR` and `FORCE_COLOR=0` do the same |

Reports are never written over a config file (also through a symlink), a `--tools` file or a folder.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | The scan finished and no `--fail-on` or `--min-score` check failed |
| 1 | A finding is at or above `--fail-on`, or the score is below `--min-score` |
| 2 | Usage error or incomplete scan: a bad option, a path or `--home` folder that does not exist, an unreadable `--tools` file, a report that could not be written, or a config file that could not be read or parsed while `--fail-on` or `--min-score` is set |

A config that cannot be read or parsed is listed under `errors` in `--json` output, which then has `complete: false`. Without `--fail-on` or `--min-score` it does not change the exit code, so a broken file in your home directory does not stop a plain scan.

## Reports

`--html` writes one self-contained file that opens offline, prints cleanly and can be sent to someone. It has the fixes in order, every server and what it runs, and each finding with the lines of config involved.

<img src="docs/report.png" width="760" alt="First page of the HTML report: score 24 of 100, grade F, a 0 to 100 scale with grade bands, and the table of fixes">

`--sarif` writes SARIF 2.1.0 for GitHub code scanning. File locations are relative to the current folder, or absolute `file:` URIs for files outside it, and a config that could not be read or parsed marks the run as not successful, with a notification for each such file. `--markdown` appends a summary for a CI job page, and `--json` prints everything as JSON.

## Hidden instructions in tool descriptions

A server's tool descriptions go to the model verbatim, and you normally never read them. A malicious or compromised server can use them to tell the model to read `~/.ssh/id_rsa` and pass it along as a harmless-looking parameter.

With `--connect`, mcpsafe starts each configured server, lists its tools over MCP (stdio, Streamable HTTP or the older SSE transport) and checks every tool and parameter description. It starts servers the way their client does: project servers in the project folder, `${VAR}`, `${env:VAR}` and `${VAR:-default}` filled in from your environment, and servers you turned off skipped. Because that runs the servers, use it only where that is acceptable. To check a saved `tools/list` response instead, pass it with `--tools file.json`. The file can hold the full JSON-RPC response (`{"jsonrpc": "2.0", "id": 1, "result": {"tools": [...]}}`), just the result (`{"tools": [...]}`), a bare tools array, or a map of servers (`{"server": [tools]}` or `{"server": {"tools": [...]}}`). The first three are named after the file, so two saved responses count as two servers; two files with the same name, such as `a/tools.json` and `b/tools.json`, are named `a/tools` and `b/tools`. In a map of servers, every entry must hold a tools list. A tool too large to read in full (over 200,000 characters of text, 20,000 schema values or 64 levels of nesting) is reported as a medium finding instead of passing as clean.

<img src="docs/finding.png" width="760" alt="A critical finding in the HTML report: the get_forecast tool description with its hidden instruction to read ~/.ssh/id_rsa highlighted">

## Checks

Where a rule gives a range, the severity depends on the finding, so check the conditions before you pick a `--fail-on` level. A finding on a server you turned off (`disabled`) is one step lower than usual, except MCS001. In SARIF, a finding whose severity differs from the rule's default gets a rule of its own, such as `MCS001-critical`, because code scanning takes the severity from the rule.

| ID | Severity | Finds |
|---|---|---|
| MCS001 | medium to critical | API keys, tokens, `Authorization` headers and database passwords in a config. High for a known token format, medium for a value that only looks like a secret, critical in a project file that is likely committed to git |
| MCS002 | medium | A config holding secrets that other users on the machine can read |
| MCS003 | medium | `npx`, `uvx` or `pipx` packages without an exact version |
| MCS004 | medium | Docker images with no tag or `:latest` |
| MCS005 | high | Remote servers on plain `http://` (localhost is fine) |
| MCS006 | high | Tokens in a server URL's query string |
| MCS007 | low to high | Servers that offer shell or command execution. High for a shell server package or a coding agent run as a server, medium when only the server's name suggests a shell, low for a server launched through an inline `sh -c` script |
| MCS008 | high | Filesystem access to `/`, `~`, `C:\` or a whole home directory, including Docker mounts |
| MCS009 | high | Containers with `--privileged`, host networking or PID namespace, extra capabilities, or the Docker socket |
| MCS010 | critical | A launch command that pipes a downloaded script into a shell |
| MCS011 | medium to high | Auto-approval: `autoApprove`, `alwaysAllow`, `trust: true`, broad `mcp__` allow rules, `bypassPermissions`. Medium for a list of named tools or servers, high when everything is approved: `trust: true`, `bypassPermissions`, a `*` wildcard or `mcp__*` |
| MCS012 | medium | Claude Code's `enableAllProjectMcpServers`, which lets any cloned repository start servers |
| MCS013 | medium to high | Package names one or two characters away from a popular MCP server, or its name without the @ (which npx reads as a GitHub repository): high. A popular server's name with its npm scope dropped (`stripe-mcp` for `@stripe/mcp`): medium |
| MCS014 | medium | Servers run from `/tmp`, `Downloads` or another temporary folder |
| MCS015 | high | Invisible Unicode (zero-width, bidirectional override, tag characters) in a config |
| MCS016 | low to critical | Hidden instructions in tool or parameter descriptions (needs `--connect` or `--tools`). Critical for clear tool poisoning, such as overriding the model's instructions or sending files and secrets somewhere; high for text that tells the model to hide what it does, or to run commands on sensitive files; medium or low for weaker signs that are worth a read |
| MCS017 | low to high | Tool shadowing. Low for the same tool name on two servers, medium for a mention of another server's tool (or a shared name where one tool also looks suspicious), high when a tool gives instructions about another server's tool |
| MCS018 | medium | Packages installed from a git branch or URL instead of a pinned release |

MCS001 does not report values that only point at a secret (`${VAR}` references, environment variable names, file paths, AWS ARNs and other secret manager names), template placeholders copied from a README (`xoxb-your-bot-token`, `{{GITHUB_TOKEN}}`), or a database URL on localhost with a well-known default password such as `postgres:postgres@127.0.0.1`. That last exception applies only when every host in the URL is local, so a replica set or a `host=` parameter that reaches another machine is still reported.

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

With no arguments it scans these files in your home directory and the project files in the current folder, without descending into subfolders. A folder passed as an argument is searched recursively. A config folder under another name (a dotfiles copy of `.cursor`, a VS Code `User` folder) works too: its `mcp.json` is read directly. Files that only a user's own setup has count as user configs even outside your home folder: `claude_desktop_config.json` in Claude Desktop's own folder (`Application Support/Claude`, `AppData/Roaming/Claude` or `.config/Claude`), `.claude.json`, and an editor's `User` folder. So does every user config in a folder that looks like a home directory. A `claude_desktop_config.json` anywhere else, such as an example committed to a repository, is a project file. Anything inside a git checkout (a folder with `.git` at or above it) is a project file too, unless it is one of the user configs of the home folder being scanned. JSON with comments and trailing commas is fine.

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

Inputs: `path` (default `.`), `fail-on` (default `high`, or `none`), `min-score`, `ignore`, `sarif` (default `mcpsafe.sarif`) and `html`. Outputs: `score`, `grade`, `findings`, `complete` (`false` when a config could not be read or parsed, so the score covers only the files that were read) and `sarif`. A `path` that does not exist fails the job, and a config that cannot be parsed gets an error annotation and fails the job while `fail-on` or `min-score` is set.

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
