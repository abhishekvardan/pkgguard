#!/usr/bin/env node
/**
 * Live end-to-end smoke test (needs network): drives the built MCP server over stdio
 * exactly as Claude Code would, then the hook entrypoint with sample events.
 *   npm run build && npm run smoke
 */
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'dist', 'cli.js');
const fixtures = join(root, 'test', 'fixtures');
let failed = 0;

function check(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `\n      ${detail}`}`);
  if (!ok) failed++;
}

async function mcpSession(requests) {
  const child = spawn(process.execPath, [cli, 'mcp'], { cwd: fixtures, stdio: ['pipe', 'pipe', 'inherit'] });
  const responses = new Map();
  let buf = '';
  child.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (line.trim()) {
        const m = JSON.parse(line);
        responses.set(m.id, m);
      }
    }
  });
  for (const r of requests) child.stdin.write(JSON.stringify(r) + '\n');
  const ids = requests.filter((r) => r.id !== undefined).map((r) => r.id);
  const deadline = Date.now() + 120000;
  while (ids.some((id) => !responses.has(id)) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
  child.stdin.end();
  return responses;
}

function hook(event) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cli, 'hook'], { stdio: ['pipe', 'pipe', 'inherit'], env: { ...process.env, CLAUDE_PROJECT_DIR: event.cwd ?? fixtures } });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.on('exit', (code) => resolve({ code, out: out.trim() ? JSON.parse(out) : undefined }));
    child.stdin.end(JSON.stringify(event));
  });
}

const call = (id, name, args) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

const r = await mcpSession([
  { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } } },
  { jsonrpc: '2.0', method: 'notifications/initialized' },
  { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  call(3, 'check_package', { ecosystem: 'npm', name: 'lodash', version: '4.17.15' }),
  call(4, 'check_package', { ecosystem: 'npm', name: 'lodash', version: '4.18.1' }),
  call(5, 'check_package', { ecosystem: 'pip', name: 'requests' }),
  call(6, 'get_vulnerability', { id: 'GHSA-p6mc-m468-83gw' }),
  call(7, 'scan_project', { path: 'npm' }),
  call(8, 'suggest_fixes', { path: 'npm', min_severity: 'high' }),
  call(9, 'check_package', { ecosystem: 'cobol', name: 'x' }),
  { jsonrpc: '2.0', id: 10, method: 'nope' },
]);

check('initialize', r.get(1)?.result?.serverInfo?.name === 'pkgguard' && r.get(1).result.protocolVersion === '2025-06-18', JSON.stringify(r.get(1)));
check('tools/list has 4 tools', r.get(2)?.result?.tools?.length === 4, JSON.stringify(r.get(2)));
const text = (id) => r.get(id)?.result?.content?.[0]?.text ?? '';
check('lodash 4.17.15 is vulnerable', /CVE-2020-8203/.test(text(3)) && r.get(3).result.structuredContent?.vulnerable === true, text(3));
check('lodash 4.18.1 is clean', /no known vulnerabilities/.test(text(4)), text(4));
check('requests history', /advisory\(ies\) on record/.test(text(5)) && /latest release/.test(text(5)), text(5));
check('get_vulnerability', /CVE-2020-8203/.test(text(6)) && /lodash/.test(text(6)), text(6));
check('scan_project finds minimist via mkdirp', /minimist@0\.0\.8 .*via mkdirp > minimist/.test(text(7)), text(7));
check('suggest_fixes gives commands', /npm install lodash@\^/.test(text(8)) && /overrides/.test(text(8)), text(8));
check('bad ecosystem is a tool error', r.get(9)?.result?.isError === true, JSON.stringify(r.get(9)));
check('unknown method is a JSON-RPC error', r.get(10)?.error?.code === -32601, JSON.stringify(r.get(10)));

const pre = await hook({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'npm install lodash@4.17.15' } });
check('PreToolUse asks on vulnerable install', pre.out?.hookSpecificOutput?.permissionDecision === 'ask' && /4\.18/.test(pre.out.hookSpecificOutput.additionalContext), JSON.stringify(pre));
const preOk = await hook({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'npm install lodash@4.18.1 && git status' } });
check('PreToolUse silent on safe install', preOk.out === undefined && preOk.code === 0, JSON.stringify(preOk));
const post = await hook({ hook_event_name: 'PostToolUse', cwd: join(fixtures, 'java'), tool_name: 'Edit', tool_input: { file_path: join(fixtures, 'java', 'pom.xml'), old_string: '2.14.0', new_string: '<log4j.version>2.14.1</log4j.version>' } });
check('PostToolUse warns after editing a pin', /log4j-core@2\.14\.1/.test(post.out?.hookSpecificOutput?.additionalContext ?? ''), JSON.stringify(post));
const start = await hook({ hook_event_name: 'SessionStart', cwd: join(fixtures, 'npm'), source: 'startup' });
check('SessionStart summarises high+ findings', /minimist@0\.0\.8/.test(start.out?.hookSpecificOutput?.additionalContext ?? ''), JSON.stringify(start));
const bad = await hook('not json');
check('hook ignores garbage input', bad.code === 0 && bad.out === undefined, JSON.stringify(bad));

console.log(failed ? `\n${failed} check(s) failed` : '\nAll smoke checks passed');
process.exit(failed ? 1 : 0);
