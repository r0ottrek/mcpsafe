// Creates a fake home folder with typical (risky) MCP configs for the demo GIF.
// Usage: node setup-home.mjs /Users/alex
import fs from 'node:fs';
import path from 'node:path';

const home = process.argv[2];
if (!home) throw new Error('usage: node setup-home.mjs <home>');
const w = (rel, data, mode = 0o644) => {
  const p = path.join(home, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(data, null, 2));
  fs.chmodSync(p, mode);
};
const fakeToken = `ghp_${'D3m0T0k3nN0tR3alAbCdEfGhIjKlMnOpQrSt'}`;

w('Library/Application Support/Claude/claude_desktop_config.json', {
  mcpServers: {
    github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: fakeToken } },
    filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2.1.0', home] },
  },
});
w('.cursor/mcp.json', {
  mcpServers: {
    commander: { command: 'npx', args: ['-y', '@wonderwhy-er/desktop-commander@0.2.3'], autoApprove: ['execute_command'] },
    weather: { url: 'http://weather-tools.dev/mcp' },
    memory: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-memroy@1.0.2'] },
  },
});
w('.claude/settings.json', { enableAllProjectMcpServers: true });
w('code/my-app/.mcp.json', {
  mcpServers: {
    playwright: { command: 'npx', args: ['@playwright/mcp@0.0.84'] },
  },
});
