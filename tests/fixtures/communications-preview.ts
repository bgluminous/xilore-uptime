import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import {communicationDb} from './communications-db.js';
import {encodeOfficialVersion} from '../../server/core/xil-version.js';
import {resetVersionQueryCache} from '../../server/features/version-query.js';

// 浏览器联调真实入口与前端，数据库完全在内存中；所有后台定时任务均被替换。
const {db} = communicationDb();
await db.execute('INSERT INTO users (id, username, password, role, email) VALUES (1, ?, ?, ?, ?)',
  ['preview', await bcrypt.hash('preview-only', 4), 'admin', 'preview@example.invalid']);
await db.execute('ALTER TABLE monitors ADD COLUMN port INTEGER');
await db.execute('ALTER TABLE monitor_groups ADD COLUMN description TEXT');
await db.execute('INSERT INTO settings VALUES (?, ?)', ['publicPageTitle', '公告与维护 · 合成验证']);
if (process.argv.includes('--timeline')) {
  const now = Date.now(), hour = 3600000;
  const announcements = [
    [1, '服务状态页更新', '欢迎使用新的公告与维护时间线。\n\n- 服务动态集中展示\n- 历史记录可在页面底部查看', 'published', 1, now - 3 * hour, now - 3 * hour],
    [2, '接口访问策略说明', '本次调整不影响现有调用方式，服务保持正常运行。', 'published', 0, now - 2 * hour, now - 2 * hour],
    [3, '上周服务升级已完成', '升级已完成，感谢理解与支持。', 'archived', 0, now - 72 * hour, now - 24 * hour]
  ];
  if (process.argv.includes('--timeline-pages')) {
    for (let id = 4; id <= 25; id++) announcements.push([id, `服务动态 ${id} · 分页与长标题换行验证`,
      '这是用于检查分页后收起、剩余条数以及键盘操作的合成公告。', 'published', 0, now - id * hour, now - id * hour]);
  }
  for (const [id, title, body, state, pinned, published, updated] of announcements) {
    await db.execute(`INSERT INTO announcements (id, title, body, state, pinned, published_ms, created_ms, updated_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [id, title, body, state, pinned, published, published, updated]);
  }
  const maintenance = [
    [1, '网站例行维护', '预计短暂影响页面访问，请稍后重试。', now + 3 * hour, now + 4 * hour, null, 'scheduled', 3],
    [2, '核心接口维护进行中', '正在进行服务配置更新，预计在计划时间内恢复。', now - hour / 2, now + hour, null, 'active', 1],
    [3, '服务例行巡检', '巡检已完成，服务运行正常。', now - 49 * hour, now - 48 * hour, null, 'completed', 1],
    [4, '维护窗口已取消', '本次维护已取消，将另行安排。', now + 12 * hour, now + 13 * hour, now - 30 * hour, 'cancelled', 3]
  ];
  for (const [id, title, body, starts, ends, cancelled, phase, monitor] of maintenance) {
    await db.execute(`INSERT INTO maintenances (id, title, body, starts_ms, ends_ms, cancelled_ms,
      phase, is_public, continue_checks, created_ms, updated_ms) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)`,
    [id, title, body, starts, ends, cancelled, phase, now, now]);
    await db.execute('INSERT INTO maintenance_monitors VALUES (?, ?)', [id, monitor]);
  }
  await db.execute('INSERT INTO maintenance_monitors VALUES (2, 2)');
}
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-communications-'));
process.env.CONFIG_PATH = path.join(directory, 'config.json');
process.env.UI_DEV_MODE = String(process.argv.includes('--readonly')); process.env.PORT = '0';
const versionPreview = process.argv.includes('--version-preview');
process.env.VERSION_CHECK_ENABLED = String(versionPreview);
process.env.VERSION_PLATFORM_CODE = 'dockerhub-linux-amd64';
process.env.VERSION_PROJECT_CODE = 'xilore-uptime';
const originalFetch = globalThis.fetch;
let versionScenario = 'new';
if (versionPreview) globalThis.fetch = (async (input: any) => {
  const url = String(input);
  if (!url.startsWith('https://raw.githubusercontent.com/')) throw new Error('预览禁止外部请求');
  if (versionScenario === 'failure') return new Response('', {status: 503});
  if (versionScenario === 'missing') return new Response('', {status: 404});
  const current = JSON.parse(fs.readFileSync('package.json', 'utf8')).version;
  const versions = ['2.5.0', current, '2.3.0', '2.2.0', '2.1.0', '2.0.0'];
  if (url.endsWith('/index.json')) return Response.json(versions.map(version => ({version, versionCode: encodeOfficialVersion(version)})));
  const version = url.endsWith('/latest.json') ? (versionScenario === 'current' ? current : '2.5.0') : url.match(/versions\/([\d.]+)\.json$/)?.[1];
  if (!version) return new Response('', {status: 404});
  return Response.json({projectCode: 'xilore-uptime', platformCode: 'dockerhub-linux-amd64', version,
    versionCode: encodeOfficialVersion(version), forceUpdate: true,
    changelog: `## v${version} 更新说明\n\n- 新增公告与维护时间线\n- 改善 **手机布局** 和键盘操作\n- 修复统计边界问题\n\n> 更新容器时请保留数据目录。\n\n<script>alert(1)</script>\n[危险链接](javascript:alert(1))`,
    downloadUrl: 'https://hub.docker.com/r/bgluminous/xilore-uptime/tags', extra: null});
}) as typeof fetch;
process.env.JWT_SECRET = 'communications-preview-synthetic-only';
fs.writeFileSync(process.env.CONFIG_PATH, JSON.stringify({installed: true, database: {
  host: 'never-connect.invalid', port: 3306, user: 'synthetic', password: 'synthetic', name: 'synthetic'
}}));
let closed = false;
const execute = async (sql: string, values?: any[]) => {
  if (/^\s*(CREATE|ALTER)\s/i.test(sql)) return [{affectedRows: 0}, []];
  if (/^SHOW /i.test(sql)) return [[{Field: 'existing'}], []];
  if (/information_schema/i.test(sql)) return [[{size_mb: 0}], []];
  // SQLite 使用通信模块的最小测试 schema；完整只读 schema 检查由 ui-dev 专项测试覆盖。
  if (/^SELECT [\w, ]+ FROM \w+ LIMIT 0$/i.test(sql)) return [[], []];
  return db.execute(sql, values);
};
let lock = Promise.resolve();
mysql.createPool = (() => ({execute, async getConnection() {
  const previous = lock;
  let unlock!: () => void;
  lock = new Promise<void>(resolve => {unlock = resolve;});
  await previous;
  return {execute, async query(sql: string) {
    if (sql !== 'SET SESSION TRANSACTION READ ONLY') throw new Error('预览不支持该会话操作');
    return [[], []];
  }, beginTransaction: () => db.execute('BEGIN'), commit: () => db.execute('COMMIT'),
    rollback: () => db.execute('ROLLBACK'), release: unlock, destroy: unlock};
}, async end() {if (!closed) {closed = true; await db.end();}}})) as any;
const originalInterval = globalThis.setInterval, originalTimeout = globalThis.setTimeout;
function protect(original: any) {
  return ((callback: any, delay: number, ...args: any[]) => {
    const caller = new Error().stack?.split('\n')[2] || '';
    if (/[/\\]server[/\\](server\.ts|features[/\\]maintenance\.ts)/.test(caller)) return {unref() {}};
    return original(callback, delay, ...args);
  }) as any;
}
globalThis.setInterval = protect(originalInterval); globalThis.setTimeout = protect(originalTimeout);
let server: any;
try {
  const {start} = await import('../../server/server.js');
  server = await start(); if (!server.listening) await once(server, 'listening');
  console.log(`COMMUNICATIONS_PREVIEW_URL=http://127.0.0.1:${server.address().port}`);
  console.log('Synthetic login: preview / preview-only. Type stop to close.');
  const input = createInterface({input: process.stdin, terminal: false});
  await new Promise<void>(resolve => {
    input.on('line', line => {
      if (line === 'stop') resolve();
      if (versionPreview && /^version (new|current|failure|missing)$/.test(line)) {
        versionScenario = line.slice(8); resetVersionQueryCache();
        console.log(`VERSION_SCENARIO=${versionScenario}`);
      }
    });
    process.once('SIGINT', resolve); process.once('SIGTERM', resolve);
  });
  input.close(); process.stdin.pause();
} finally {
  globalThis.setInterval = originalInterval; globalThis.setTimeout = originalTimeout;
  globalThis.fetch = originalFetch;
  if (server) await new Promise<void>(resolve => server.close(() => resolve()));
  if (!closed) await db.end();
  const resolved = path.resolve(directory);
  if (path.dirname(resolved) !== path.resolve(os.tmpdir()) || !path.basename(resolved).startsWith('uptime-communications-')) {
    throw new Error('预览临时目录不在预期范围内');
  }
  fs.rmSync(resolved, {recursive: true});
}
