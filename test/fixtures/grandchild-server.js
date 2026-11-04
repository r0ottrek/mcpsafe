// A stdio MCP server that first starts a long-lived grandchild, the way a
// wrapper (npx, uvx, sh -c, docker) leaves processes behind. The grandchild
// ignores SIGTERM and shares the server's stdout, so it also holds mcpsafe's
// pipe open. Its pid is written to GCPIDFILE. argv[2] is passed on to
// live-server.js as its mode (normal, ignoreterm, hang, ...).
import { spawn } from 'node:child_process';
import fs from 'node:fs';

const gc = spawn(process.execPath, ['-e', "process.on('SIGTERM',()=>{});setInterval(()=>{},1e9)"], { stdio: ['ignore', 'inherit', 'ignore'] });
fs.writeFileSync(process.env.GCPIDFILE, String(gc.pid));
await import('./live-server.js');
