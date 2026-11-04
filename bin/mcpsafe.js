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
import { safe } from '../src/report/text.js';

const HELP = `mcpsafe ${VERSION}
Audit MCP server and AI agent configs for risky setups.

Usage
  mcpsafe [paths...] [options]

With no paths, scans the MCP configs in your home directory (Claude Desktop,
Claude Code, Cursor, VS Code, Windsurf, Cline, Roo Code, Gemini CLI) plus the
project configs in the current folder (not its subfolders). Paths can be config
files or folders; folders are searched recursively.

Options
  --no-home             Skip user-level configs; scan only the given paths,
                        or the current folder if none are given
  --home <dir>          Treat <dir> as the home directory
  --connect             Start each server and check its tool descriptions
                        for hidden instructions (runs the servers!)
  --tools <file>        Check tool descriptions from a saved tools/list
                        response or tools array (can be repeated)
  --html [file.html]    Write an HTML report (default: mcpsafe-report.html).
                        The file name must end in .html; use --html=<file>
                        for any other name
  --sarif <file>        Write SARIF for GitHub code scanning
  --markdown <file>     Append a Markdown summary (handy for CI job summaries)
  --json                Print results as JSON instead of the terminal report
  --fail-on <severity>  Exit with code 1 if any finding is at or above
                        critical | high | medium | low
  --min-score <n>       Exit with code 1 if the score is below n (0 to 100)
  --ignore <ids>        Comma-separated rule IDs to skip, e.g. MCS003,MCS004
                        (can be repeated)
  -v, --verbose         Show each finding in its config file, with the fix
  --no-color            Disable colors (also honors NO_COLOR and FORCE_COLOR=0)
  --rules               List all rules
  --version             Print version
  -h, --help            Show this help

Exit codes
  0  The scan finished and no --fail-on or --min-score check failed
  1  A finding is at or above --fail-on, or the score is below --min-score
  2  Usage error or incomplete scan: a bad option, a path that does not
     exist, an unreadable --tools file, a report that could not be written,
     or a config file that could not be read or parsed while --fail-on or
     --min-score is set
`;

const HTML_DEFAULT = 'mcpsafe-report.html';

// A bare --html takes no value, so `mcpsafe --html .mcp.json` scans .mcp.json
// instead of writing the report over it. The next token is taken as the
// report name only when it ends in .html or .htm; --html=<file> takes any name.
function normalizeArgs(argv) {
  const args = [];
  let bareHtml = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { args.push(...argv.slice(i)); break; }
    args.push(a);
    if (a !== '--html') continue;
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('-') && /\.html?$/i.test(next)) { args.push(next); i++; } else { args.push(HTML_DEFAULT); bareHtml = true; }
  }
  return { args, bareHtml };
}

// Files mcpsafe reads as configs. A report is never written over one.
const CONFIG_NAMES = new Set(['.mcp.json', 'mcp.json', '.claude.json', 'settings.json', 'settings.local.json', 'claude_desktop_config.json', 'mcp_config.json', 'cline_mcp_settings.json', 'mcp_settings.json']);

function parseMinScore(raw) {
  if (raw === undefined || raw.trim() === '') return { value: undefined };
  const s = raw.trim();
  const n = /^\d+(\.\d+)?$/.test(s) ? Number(s) : NaN;
  if (!Number.isFinite(n) || n < 0 || n > 100) return { error: `--min-score must be a number from 0 to 100, got "${raw}"` };
  return { value: n };
}

function colorEnabled(v) {
  if (v['no-color'] || v.json || process.env.NO_COLOR) return false;
  const fc = process.env.FORCE_COLOR;
  if (fc === '0' || fc === 'false') return false;
  return !!process.stdout.isTTY || (fc !== undefined && fc !== '');
}

function main() {
  const { args, bareHtml } = normalizeArgs(process.argv.slice(2));
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        'no-home': { type: 'boolean' }, home: { type: 'string' }, connect: { type: 'boolean' },
        tools: { type: 'string', multiple: true }, html: { type: 'string' }, sarif: { type: 'string' }, markdown: { type: 'string' },
        json: { type: 'boolean' }, 'fail-on': { type: 'string' }, 'min-score': { type: 'string' },
        ignore: { type: 'string', multiple: true }, verbose: { type: 'boolean', short: 'v' }, 'no-color': { type: 'boolean' },
        rules: { type: 'boolean' }, version: { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (e) {
    console.error(`mcpsafe: ${safe(e.message)}\nRun mcpsafe --help for usage.`);
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
  const minScore = parseMinScore(v['min-score']);
  if (minScore.error) {
    console.error(`mcpsafe: ${minScore.error}`);
    return Promise.resolve(2);
  }
  const gated = !!v['fail-on'] || minScore.value !== undefined;

  const includeHome = !v['no-home'];
  // With no paths, scan the current folder, with or without --no-home.
  const paths = positionals.length ? positionals : [process.cwd()];
  const color = colorEnabled(v);

  return scan({
    paths,
    // With no paths we only look at the current folder itself, not every
    // project below it. Folders passed explicitly are searched recursively.
    depth: positionals.length ? 6 : 0,
    home: v.home ? path.resolve(v.home) : undefined,
    includeHome,
    connect: v.connect,
    toolsFiles: v.tools,
    ignore: (v.ignore || []).flatMap((s) => s.split(',')).map((s) => s.trim()).filter(Boolean),
    onProgress: (m) => { if (process.stderr.isTTY && !v.json) process.stderr.write(`\r\x1b[2K  ${safe(m)}`); },
  }).then((result) => {
    if (process.stderr.isTTY && v.connect && !v.json) process.stderr.write('\r\x1b[2K');
    if (v.json) process.stdout.write(`${JSON.stringify(toJson(result), null, 2)}\n`);
    else process.stdout.write(`${renderTerminal(result, { color, verbose: v.verbose, width: Math.min(process.stdout.columns || Number(process.env.COLUMNS) || 100, 120) })}\n`);

    // Write every requested report, even if an earlier one fails.
    const configPaths = new Set(result.configs.map((c) => path.resolve(c.source.path)));
    let writeFailed = false;
    const refuse = (file, htmlOnly) => {
      const abs = path.resolve(file);
      let st = null;
      try { st = fs.statSync(abs); } catch { /* does not exist yet */ }
      if (st?.isDirectory()) return 'it is a folder';
      if (configPaths.has(abs) || CONFIG_NAMES.has(path.basename(abs).toLowerCase())) return 'it is an MCP config file';
      if (htmlOnly && st && !/\.html?$/i.test(abs)) return 'the file exists and its name does not end in .html';
      return null;
    };
    const output = (kind, file, write, htmlOnly = false) => {
      const why = refuse(file, htmlOnly);
      if (why) {
        console.error(`mcpsafe: not writing the ${kind} to ${safe(path.resolve(file))}: ${safe(why)}`);
        writeFailed = true;
        return null;
      }
      try {
        return write(path.resolve(file));
      } catch (e) {
        const why = { ENOENT: 'its folder does not exist', EACCES: 'permission denied', EPERM: 'permission denied', EROFS: 'read-only file system' }[e.code] || e.message;
        console.error(`mcpsafe: could not write the ${kind} to ${safe(path.resolve(file))}: ${safe(why)}`);
        writeFailed = true;
        return null;
      }
    };

    if (v.html) {
      const out = output('HTML report', v.html, (abs) => {
        try {
          fs.writeFileSync(abs, renderHtml(result));
          return abs;
        } catch (e) {
          // With a bare --html the current folder may not be writable (e.g.
          // C:\Windows\System32). Fall back to the temp folder rather than
          // failing after the scan. A path the user named is never moved.
          if (!bareHtml || !['EPERM', 'EACCES', 'EROFS'].includes(e.code)) throw e;
          const tmp = path.join(os.tmpdir(), path.basename(abs));
          fs.writeFileSync(tmp, renderHtml(result));
          return tmp;
        }
      }, true);
      if (out && !v.json) console.log(`HTML report written to ${out}`);
    }
    if (v.sarif) {
      const out = output('SARIF report', v.sarif, (abs) => { fs.writeFileSync(abs, renderSarif(result)); return abs; });
      if (out && !v.json) console.log(`SARIF written to ${out}`);
    }
    if (v.markdown) output('Markdown summary', v.markdown, (abs) => { fs.appendFileSync(abs, renderMarkdown(result)); return abs; });

    let code = 0;
    if (v['fail-on'] && atOrAbove(result.findings, v['fail-on']).length) code = 1;
    if (minScore.value !== undefined && result.score.value < minScore.value) code = 1;

    // An incomplete scan must not pass a gate.
    const errors = result.errors || [];
    const missing = errors.filter((e) => e.missing);
    const unreadable = errors.filter((e) => !e.missing);
    for (const e of missing) console.error(`mcpsafe: path not found: ${safe(e.path)}`);
    if (unreadable.length && gated) {
      const n = unreadable.length;
      console.error(`mcpsafe: ${n} config file${n === 1 ? '' : 's'} could not be read or parsed, so the scan is incomplete and cannot pass --fail-on or --min-score`);
      for (const e of unreadable) console.error(`  ${safe(e.path)}: ${safe(e.error)}`);
    }
    if (missing.length || (unreadable.length && gated) || writeFailed) code = 2;
    return code;
  });
}

main().then((code) => { process.exitCode = code; }).catch((e) => {
  if (e?.expected || !process.env.MCPSAFE_DEBUG) {
    console.error(`mcpsafe: ${safe(e?.message ?? e)}`);
    if (!e?.expected) console.error('Set MCPSAFE_DEBUG=1 to see the stack trace.');
  } else {
    console.error(`mcpsafe: ${e.stack || e.message}`);
  }
  process.exitCode = 2;
});
