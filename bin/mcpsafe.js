#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { parseArgs } from 'node:util';
import { scan, atOrAbove, toJson, VERSION } from '../src/scan.js';
import { renderTerminal } from '../src/report/terminal.js';
import { renderHtml } from '../src/report/html.js';
import { renderSarif } from '../src/report/sarif.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { ruleList, SEVERITIES } from '../src/rules.js';

const HELP = `mcpsafe ${VERSION}
Audit MCP server and AI agent configs for risky setups.

Usage
  mcpsafe [paths...] [options]

With no paths, scans the MCP configs in your home directory (Claude Desktop,
Claude Code, Cursor, VS Code, Windsurf, Cline, Roo Code, Gemini CLI) plus the
project configs in the current folder (not its subfolders). Paths can be config
files or folders; folders are searched recursively.

Options
  --no-home             Skip user-level configs; only scan the given paths
  --home <dir>          Treat <dir> as the home directory
  --connect             Start each server and check its tool descriptions
                        for hidden instructions (runs the servers!)
  --tools <file>        Check tool descriptions from a saved tools/list JSON
  --html [file]         Write an HTML report (default: mcpsafe-report.html)
  --sarif <file>        Write SARIF for GitHub code scanning
  --markdown <file>     Write a Markdown summary (handy for CI job summaries)
  --json                Print results as JSON instead of the terminal report
  --fail-on <severity>  Exit with code 1 if any finding is at or above
                        critical | high | medium | low
  --min-score <n>       Exit with code 1 if the score is below n
  --ignore <ids>        Comma-separated rule IDs to skip, e.g. MCS003,MCS004
  -v, --verbose         Show each finding in its config file, with the fix
  --no-color            Disable colors (also honors NO_COLOR)
  --rules               List all rules
  --version             Print version
  -h, --help            Show this help
`;

function main() {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        'no-home': { type: 'boolean' }, home: { type: 'string' }, connect: { type: 'boolean' },
        tools: { type: 'string', multiple: true }, html: { type: 'string' }, sarif: { type: 'string' }, markdown: { type: 'string' },
        json: { type: 'boolean' }, 'fail-on': { type: 'string' }, 'min-score': { type: 'string' },
        ignore: { type: 'string' }, verbose: { type: 'boolean', short: 'v' }, 'no-color': { type: 'boolean' },
        rules: { type: 'boolean' }, version: { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (e) {
    // Allow a bare --html with no file name.
    const i = process.argv.indexOf('--html');
    if (i > 0 && (i === process.argv.length - 1 || process.argv[i + 1].startsWith('-'))) {
      process.argv.splice(i + 1, 0, 'mcpsafe-report.html');
      return main();
    }
    console.error(`mcpsafe: ${e.message}\nRun mcpsafe --help for usage.`);
    return Promise.resolve(2);
  }
  const { values: v, positionals } = parsed;
  if (v.help) { process.stdout.write(HELP); return Promise.resolve(0); }
  if (v.version) { console.log(VERSION); return Promise.resolve(0); }
  if (v.rules) {
    for (const r of ruleList()) console.log(`${r.id}  ${r.severity.padEnd(8)}  ${r.title}`);
    return Promise.resolve(0);
  }
  if (v['fail-on'] && !SEVERITIES.includes(v['fail-on'])) {
    console.error(`mcpsafe: --fail-on must be one of ${SEVERITIES.join(', ')}`);
    return Promise.resolve(2);
  }

  const includeHome = !v['no-home'];
  const paths = positionals.length ? positionals : [process.cwd()];
  const color = !v['no-color'] && !process.env.NO_COLOR && (process.stdout.isTTY || !!process.env.FORCE_COLOR) && !v.json;

  return scan({
    paths,
    // With no paths we only look at the current folder itself, not every
    // project below it. Folders passed explicitly are searched recursively.
    depth: positionals.length ? 6 : 0,
    home: v.home ? path.resolve(v.home) : undefined,
    includeHome,
    connect: v.connect,
    toolsFiles: v.tools,
    ignore: v.ignore ? v.ignore.split(',').map((s) => s.trim()) : [],
    onProgress: (m) => { if (process.stderr.isTTY && !v.json) process.stderr.write(`\r\x1b[2K  ${m}`); },
  }).then((result) => {
    if (process.stderr.isTTY && v.connect && !v.json) process.stderr.write('\r\x1b[2K');
    if (v.json) process.stdout.write(`${JSON.stringify(toJson(result), null, 2)}\n`);
    else process.stdout.write(`${renderTerminal(result, { color, verbose: v.verbose, width: Math.min(process.stdout.columns || Number(process.env.COLUMNS) || 100, 120) })}\n`);

    if (v.html) {
      let out = path.resolve(v.html);
      try {
        fs.writeFileSync(out, renderHtml(result));
      } catch (e) {
        // The current folder may not be writable (e.g. C:\Windows\System32).
        // Fall back to the temp folder rather than failing after the scan.
        if (!['EPERM', 'EACCES', 'EROFS'].includes(e.code)) throw e;
        out = path.join(os.tmpdir(), path.basename(v.html));
        fs.writeFileSync(out, renderHtml(result));
      }
      if (!v.json) console.log(`HTML report written to ${out}`);
    }
    if (v.sarif) {
      fs.writeFileSync(v.sarif, renderSarif(result));
      if (!v.json) console.log(`SARIF written to ${path.resolve(v.sarif)}`);
    }

    if (v.markdown) fs.appendFileSync(v.markdown, renderMarkdown(result));

    let code = 0;
    if (v['fail-on'] && atOrAbove(result.findings, v['fail-on']).length) code = 1;
    if (v['min-score'] && result.score.value < Number(v['min-score'])) code = 1;
    return code;
  });
}

main().then((code) => { process.exitCode = code; }).catch((e) => {
  console.error(`mcpsafe: ${e.stack || e.message}`);
  process.exitCode = 2;
});
