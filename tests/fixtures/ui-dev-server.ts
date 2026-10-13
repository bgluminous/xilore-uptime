import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';

// 全部凭据、用户及监控均为合成数据；不读取工作区配置，也不创建真实数据库连接。
const scenario = process.argv[2] || 'readonly';
const originalNow = Date.now;
const fixtureEnd = Date.now();
const groupScenario = scenario === 'group-status' || scenario === 'preview-groups';
const isPreview = scenario === 'preview' || scenario === 'preview-groups';
const withHistory = scenario === 'response-stats' || isPreview || groupScenario;
if (scenario === 'response-stats') Date.now = () => fixtureEnd;
const testDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-ui-dev-'));
const configPath = path.join(testDirectory, 'config.json');
process.env.CONFIG_PATH = configPath;
process.env.PORT = '0';
process.env.JWT_SECRET = 'ui-development-test-only-secret';
process.env.UI_DEV_MODE = scenario === 'normal' ? 'false' : scenario === 'bad-mode' ? 'yes' : 'true';
process.env.VERSION_CHECK_ENABLED = 'false';
if (scenario !== 'missing-config') fs.writeFileSync(configPath, scenario === 'bad-json' ? '{invalid' : JSON.stringify({
  installed: true, uiDevMode: true,
  database: {host: 'ui-dev-test.invalid', port: 3306, user: 'fixture', password: 'synthetic-only', name: 'fixture'}
}));

const groups = [{id: 1, name: '演示服务', sort_order: 0}, {id: 2, name: '后台任务', sort_order: 0}];
const monitor = {id: 1, name: 'UI 只读验证服务', type: 'http', target: 'https://example.invalid',
  group_id: 1, status: 'up', enabled: 1, is_public: 1, interval_seconds: 60, timeout_seconds: 10,
  retries: 0, expected_status: 200, last_response_time: 86, last_check: new Date(), ssl_days_remaining: 42,
  email_notification: 0, webhook_notification: 0, feishu_notification: 0};
const monitors = withHistory ? [monitor,
  {...monitor, id: 2, name: '零毫秒服务', last_response_time: 0},
  {...monitor, id: 3, name: '私有服务', group_id: 2, is_public: 0, last_response_time: 90000, ssl_days_remaining: null},
  {...monitor, id: 4, name: '离线服务', status: 'down', last_response_time: null},
  {...monitor, id: 5, name: '暂无记录', group_id: 2, status: 'unknown', last_response_time: null}
] : [monitor];
if (groupScenario) {
  groups[0].name = '核心服务';
  groups.push({id: 3, name: '健康服务', sort_order: 1}, {id: 4, name: '暂停服务', sort_order: 2},
    {id: 5, name: '空分组', sort_order: 3});
  Object.assign(monitors[0], {name: 'API'});
  Object.assign(monitors[1], {name: '数据库', status: 'warning'});
  Object.assign(monitors[2], {name: '私有离线服务', status: 'down'});
  Object.assign(monitors[3], {name: '官网'});
  Object.assign(monitors[4], {name: '等待检测'});
  monitors.push({...monitor, id: 6, name: '健康服务', group_id: 3},
    {...monitor, id: 7, name: '暂停离线服务', group_id: 4, status: 'down', enabled: 0},
    {...monitor, id: 8, name: '未分组服务', group_id: 0});
}
const historyRecord = (id: number, monitorId: number, response: number | null, ago: number) => ({
  id, monitor_id: monitorId, response_time: response, checked_at: new Date(fixtureEnd - ago),
  status: response === null ? 'down' : 'up', message: response === null ? '请求超时' : '检测成功'
});
const history = withHistory ? [
  ...Array.from({length: 200}, (_, i) => historyRecord(i + 1, 1, i + 1, 60000 + i * 10000)),
  ...[2, 8, 18, 48, 240].map((hours, i) => historyRecord(201 + i, 1, 400 * 2 ** i, hours * 3600000)),
  historyRecord(301, 2, 0, 60000), historyRecord(302, 2, null, 120000),
  historyRecord(303, 3, 90000, 60000), historyRecord(304, 4, null, 60000)
] : [];
if (groupScenario) {
  history.length = 0;
  for (const item of monitors.filter(row => row.status !== 'unknown')) {
    for (let slot = 0; slot < 288; slot++) {
      // 近期异常叠加在完整的正常历史上，另含少量缺失区间。
      if (item.id === 1 && slot > 200 && slot < 210) continue;
      const status = slot < 6 ? item.status : 'up';
      history.push({...historyRecord(1000 + item.id * 288 + slot, item.id,
        status === 'down' ? null : 86, slot * 300000 + 60000), status});
    }
  }
}
const user = {id: 1, username: 'preview', password: await bcrypt.hash('preview-only', 4), role: 'admin', email: 'preview@example.invalid'};
const settings = {publicPageTitle: '只读模式验证', logRetentionDays: '30', smtpHost: 'smtp.example.invalid', smtpUser: 'preview', smtpPort: '587'};
const queries: string[] = [];
const queryCalls: {sql: string; values: any[]}[] = [];
let failNextHistory = false, delayNextHistory = false, statusBarsUnavailable = false;
let poolCreated = 0, ended = false, destroyed = false;
function rowsFor(sql: string, values: any[] = []): any[] {
  queries.push(sql);
  queryCalls.push({sql, values});
  if (scenario === 'missing-column' && /FROM monitors LIMIT 0/i.test(sql)) throw new Error('Unknown column');
  if (/LIMIT 0/i.test(sql)) return [];
  if (/^SHOW COLUMNS/i.test(sql)) return sql.includes('timeout_ms') ? [] : [{Field: 'existing'}];
  if (/^SHOW TABLES/i.test(sql)) return [{table: 'existing'}];
  if (/^SELECT 1$/i.test(sql)) return [{value: 1}];
  if (!/^SELECT/i.test(sql.trim())) return {insertId: 2, affectedRows: 1} as any;
  if (/^SELECT \(SELECT COUNT\(\*\) FROM announcements WHERE state = \?\)/i.test(sql)) return [{total: 0}];
  if (/FROM (?:maintenances|maintenance_runtime|maintenance_monitors|announcements|content_deliveries)/i.test(sql)) return [];
  if (/FROM users/i.test(sql)) return /COUNT/i.test(sql) ? [{count: scenario === 'no-admin' ? 0 : 1}] : [user];
  if (/information_schema/i.test(sql)) return [{size_mb: '0.1'}];
  if (/FROM settings/i.test(sql)) return values.filter(key => key in settings).map(key => ({key_name: key, value: settings[key]}));
  if (/FROM monitor_groups/i.test(sql) && !/JOIN/i.test(sql)) {
    if (/WHERE name/i.test(sql)) return [];
    if (/MAX\(/i.test(sql)) return [{max_order: 2}];
    return groups;
  }
  if (withHistory && /FROM check_history/i.test(sql)) {
    const dates = values.filter(value => value instanceof Date) as Date[];
    const ids = values.filter(value => !(value instanceof Date)).map(Number);
    const start = dates[0]?.getTime() ?? fixtureEnd - 86400000;
    const end = dates[1]?.getTime() ?? fixtureEnd;
    const rows = history.filter(row => (!ids.length || ids.includes(row.monitor_id)) &&
      row.checked_at.getTime() >= start && row.checked_at.getTime() < end &&
      (!/response_time IS NOT NULL/i.test(sql) || row.response_time !== null));
    if (/GROUP BY monitor_id/i.test(sql)) return [...new Set(rows.map(row => row.monitor_id))].map(id => ({
      monitor_id: id, total_checks: rows.filter(row => row.monitor_id === id).length,
      up_checks: rows.filter(row => row.monitor_id === id && row.status === 'up').length
    }));
    if (/MIN\(response_time\)/i.test(sql)) {
      const responses = rows.flatMap(row => row.response_time === null ? [] : [row.response_time]);
      return [{total: rows.length, up_count: rows.filter(row => row.status === 'up').length,
        min_response: responses.length ? Math.min(...responses) : null,
        max_response: responses.length ? Math.max(...responses) : null}];
    }
    rows.sort((a, b) => a.checked_at.getTime() - b.checked_at.getTime());
    if (/ORDER BY checked_at DESC/i.test(sql)) rows.reverse();
    return /LIMIT 100/i.test(sql) ? rows.slice(0, 100) : rows;
  }
  if (groupScenario && /COUNT\(\*\)/i.test(sql) && /FROM monitors/i.test(sql) && !/JOIN/i.test(sql)) {
    const visible = monitors.filter(row => (!/is_public = 1/i.test(sql) || row.is_public === 1) &&
      (!/WHERE[\s\S]*enabled = 1/i.test(sql) || row.enabled === 1));
    return [{total: visible.length, up: visible.filter(row => row.enabled && row.status === 'up').length,
      down: visible.filter(row => row.enabled && row.status === 'down').length,
      unknown: visible.filter(row => row.enabled && row.status === 'unknown').length,
      paused: visible.filter(row => !row.enabled).length}];
  }
  if (/COUNT\(|SUM\(|AVG\(/i.test(sql)) return [{total: 1, up: 1, down: 0, paused: 0, count: 0,
    avg_uptime: 100, monitor_id: 1, total_checks: 10, up_checks: 10, down_checks: 0, uptime: 100, avg_response: 86}];
  if (/FROM check_history/i.test(sql)) return [];
  if (/SELECT id FROM monitors/i.test(sql)) return monitors.filter(row => !/is_public = 1/i.test(sql) || row.is_public === 1).map(({id}) => ({id}));
  if (/SELECT \* FROM monitors WHERE enabled/i.test(sql) && scenario === 'normal') return [];
  if (/SELECT DISTINCT g.id/i.test(sql)) return groupScenario
    ? groups.filter(group => monitors.some(row => row.is_public === 1 && row.group_id === group.id)) : groups;
  if (/FROM monitors/i.test(sql)) return monitors.filter(row =>
    (!/is_public = 1/i.test(sql) || row.is_public === 1) && (!/WHERE id = \?/i.test(sql) || row.id === Number(values[0]))
  ).map(row => ({...row}));
  throw new Error(`未覆盖的测试查询：${sql}`);
}
async function executeFixtureQuery(sql: string, values: any[]) {
  if (isPreview && statusBarsUnavailable && /SELECT monitor_id, status, checked_at, message/i.test(sql)) {
    throw new Error('合成数据：模拟状态条加载失败');
  }
  if (isPreview && /MIN\(response_time\)/i.test(sql)) {
    if (failNextHistory) {
      failNextHistory = false;
      throw new Error('合成数据：模拟一次历史加载失败');
    }
    if (delayNextHistory) {
      delayNextHistory = false;
      await new Promise(resolve => realTimeout(resolve, 2000));
    }
  }
  return [rowsFor(sql, values), []];
}
mysql.createPool = (() => {
  poolCreated++;
  return {
    execute: executeFixtureQuery,
    getConnection: async () => {
      let readOnly = false;
      return {
        query: async (sql: string) => {
          assert.equal(sql, 'SET SESSION TRANSACTION READ ONLY');
          if (scenario === 'protection-failure') throw new Error('protection failed');
          readOnly = true;
          return [[], []];
        },
        execute: async (sql: string, values: any[]) => {
          assert.equal(readOnly, true, '查询必须等待只读设置成功');
          return executeFixtureQuery(sql, values);
        },
        release() {}, destroy() {destroyed = true;}
      };
    },
    end: async () => {ended = true;}
  };
}) as any;

const applicationTimers: {delay: number; callback: (...args: any[]) => any; args: any[]}[] = [];
const realInterval = globalThis.setInterval;
const realTimeout = globalThis.setTimeout;
function interceptTimer(original: any) {
  return ((callback: any, delay: number, ...args: any[]) => {
    const caller = new Error().stack?.split('\n')[2] || '';
    if (/[/\\]server[/\\]server\.ts/.test(caller)) {
      applicationTimers.push({delay, callback, args});
      return {unref() {}, ref() {}};
    }
    return original(callback, delay, ...args);
  }) as any;
}
globalThis.setInterval = interceptTimer(realInterval);
globalThis.setTimeout = interceptTimer(realTimeout);

let server: Awaited<ReturnType<typeof import('../../server/server.js').start>> | undefined;
try {
  const {start} = await import('../../server/server.js');
  assert.equal(applicationTimers.length, 0, '导入模块不应启动后台任务');
  const expectedError: Record<string, RegExp> = {
    'missing-config': /已有数据库/, 'bad-json': /JSON/, 'bad-mode': /UI_DEV_MODE/,
    'no-admin': /已有管理员/, 'missing-column': /已有表结构/, 'protection-failure': /protection failed/
  };
  if (expectedError[scenario]) {
    await assert.rejects(start(), expectedError[scenario]);
    assert.equal(applicationTimers.length, 0);
    if (['missing-config', 'bad-json', 'bad-mode'].includes(scenario)) assert.equal(poolCreated, 0);
    else assert.equal(ended, true, '启动失败关闭连接池');
    if (scenario === 'protection-failure') assert.equal(destroyed, true);
  } else {
    server = await start();
    if (!server.listening) await once(server, 'listening');
    globalThis.setInterval = realInterval;
    globalThis.setTimeout = realTimeout;
    const address = server.address();
    assert(address && typeof address === 'object');
    const baseUrl = `http://127.0.0.1:${address.port}`;
    if (isPreview) {
      console.log(`UI_PREVIEW_URL=${baseUrl}`);
      console.log('合成数据账号：preview / preview-only');
      // 只影响合成预览，供浏览器验证失败重试和迟到响应；不增加应用接口。
      console.log('预览命令：fail-next-history / delay-next-history / statusbars-off / statusbars-on / recover-services / fail-service / stop');
      const controls = createInterface({input: process.stdin, terminal: false});
      await new Promise<void>(resolve => {
        process.once('SIGINT', resolve);
        process.once('SIGTERM', resolve);
        controls.on('line', command => {
          if (command === 'fail-next-history') failNextHistory = true;
          if (command === 'delay-next-history') delayNextHistory = true;
          if (command === 'statusbars-off') statusBarsUnavailable = true;
          if (command === 'statusbars-on') statusBarsUnavailable = false;
          if (groupScenario && command === 'recover-services') {
            for (const item of monitors.filter(row => row.id === 2 || row.id === 4)) item.status = 'up';
          }
          if (groupScenario && command === 'fail-service') monitors.find(row => row.id === 6)!.status = 'down';
          if (command === 'stop') resolve();
        });
      });
      controls.close();
      process.stdin.pause();
    } else {
      let cookie = '';
      const request = (url: string, method = 'GET', body?: object) => fetch(baseUrl + url, {
        method, headers: {'Content-Type': 'application/json', Cookie: cookie},
        body: body === undefined ? undefined : JSON.stringify(body)
      }).catch(error => { throw new Error(`${method} ${baseUrl + url}: ${String(error.cause || error)}`); });
      const status = await request('/api/install/status');
      assert.equal(status.headers.get('cache-control'), 'no-store');
      assert.deepEqual(await status.json(), {installed: true, initialized: true, uiDevMode: scenario !== 'normal'});
      assert.equal((await request('/api/content/preview', 'POST', {body: '**预览**'})).status, 401);
      const login = await request('/api/auth/login', 'POST', {username: 'preview', password: 'preview-only'});
      assert.equal(login.status, 200);
      assert.equal((await login.json()).success, true);
      cookie = login.headers.get('set-cookie')!.split(';')[0];
      const previousPreviewQueries = queries.length;
      const preview = await request('/api/content/preview', 'POST', {body: '<script>test</script>\n\n**预览**'});
      assert.equal(preview.status, 200);
      const previewData = await preview.json();
      assert.match(previewData.html, /<strong>预览<\/strong>/);
      assert(!previewData.html.includes('<script>'));
      assert(queries.slice(previousPreviewQueries).every(sql => /^SELECT COUNT\(\*\) as count FROM users WHERE role = \?$/i.test(sql)),
        '预览仅经过通用初始化校验，不读写公告、维护或检测数据');
      for (const url of ['/api/auth/me', '/api/groups', '/api/monitors', '/api/settings', '/api/stats',
        '/api/monitors/1/history', '/api/monitors/statusbars', '/api/public/groups', '/api/public/monitors',
        '/api/public/stats', '/api/public/monitors/statusbars', '/api/version', '/api/version/check', '/manage', '/', '/index.html',
        '/setup.html', '/api/announcements', '/api/maintenances', '/api/public/announcements',
        '/api/public/maintenances', '/api/public/updates', '/api/public/updates?history=1']) {
        const response = await request(url);
        const bodyText = await response.text();
        assert.equal(response.status, 200, `${url}: ${bodyText}`);
        if (url === '/api/version') {
          const body = JSON.parse(bodyText);
          const packageVersion = JSON.parse(fs.readFileSync('package.json', 'utf8')).version;
          assert.equal(body.version, packageVersion);
          assert.equal(body.latest, undefined);
        }
        if (url === '/api/version/check') {
          const body = JSON.parse(bodyText);
          assert.equal(body.checkEnabled, false);
          assert.equal(body.latest, null);
          assert.equal(body.checkFailed, false);
          assert.equal(body.checkError, null);
        }
      }
      if (scenario === 'response-stats') {
        assert.equal((await fetch(baseUrl + '/api/monitors')).status, 401);
        for (const [url, expectedIds] of [['/api/monitors', [1, 2, 3, 4, 5]], ['/api/public/monitors', [1, 2, 4, 5]]] as const) {
          const firstQuery = queryCalls.length;
          const list = await (await request(url)).json();
          assert.deepEqual(list.map((row: any) => row.id), expectedIds);
          const batchCalls = queryCalls.slice(firstQuery).filter(call => /SELECT monitor_id, response_time/i.test(call.sql));
          assert.equal(batchCalls.length, 1);
          assert.deepEqual(batchCalls[0].values.slice(0, -2), expectedIds);
          const statsOf = (id: number) => {
            const row = list.find((item: any) => item.id === id);
            assert(!('p95_response_24h' in row));
            return [row.avg_response_24h, row.p99_response_24h];
          };
          assert.deepEqual(statsOf(1), [113, 400]);
          assert.deepEqual(statsOf(2), [0, 0]);
          assert.deepEqual(statsOf(4), [null, null]);
          assert.deepEqual(statsOf(5), [null, null]);
          if (url === '/api/monitors') assert.deepEqual(statsOf(3), [90000, 90000]);
        }
        for (const [range, hours, avg, p99, count] of [
          ['1h', 1, 101, 198, 200], ['6h', 6, 102, 199, 201], ['12h', 12, 105, 200, 202],
          ['24h', 24, 113, 400, 203], ['7d', 168, 128, 800, 204], ['30d', 720, 159, 1600, 205]
        ] as const) {
          const firstQuery = queryCalls.length;
          const data = await (await request(`/api/monitors/1/history?range=${range}`)).json();
          assert(!('p95Response' in data.stats));
          assert.deepEqual([data.stats.avgResponse, data.stats.p99Response], [avg, p99]);
          assert.equal(data.stats.total, count);
          assert.equal(data.history.length, 100);
          assert.equal(data.chartData.reduce((sum: number, point: any) => sum + point.count, 0), count);
          const calls = queryCalls.slice(firstQuery).filter(call => /FROM check_history/i.test(call.sql));
          assert.equal(calls.length, 3, '详情复用原始历史，不增加查询');
          for (const call of calls) assert.deepEqual(call.values, ['1', new Date(fixtureEnd - hours * 3600000), new Date(fixtureEnd)]);
        }
        for (const id of [2, 4, 5]) {
          const data = await (await request(`/api/monitors/${id}/history`)).json();
          assert.deepEqual([data.stats.avgResponse, data.stats.p99Response], id === 2 ? [0, 0] : [null, null]);
        }
      }
      if (scenario === 'group-status') {
        const publicIds = [1, 2, 4, 5, 6, 7, 8];
        const publicList = await (await request('/api/public/monitors')).json();
        assert.deepEqual(publicList.map((row: any) => row.id), publicIds);
        assert(!JSON.stringify(publicList).includes('私有离线服务'));
        const publicGroups = await (await request('/api/public/groups')).json();
        assert.deepEqual(publicGroups.map((row: any) => row.id), [1, 2, 3, 4]);
        for (const [url, ids] of [['/api/public/monitors/statusbars', publicIds],
          ['/api/monitors/statusbars', monitors.map(row => row.id)]] as const) {
          const before = queryCalls.length;
          const result = await (await request(url)).json();
          assert.deepEqual(result.map((row: any) => row.monitorId), ids);
          const calls = queryCalls.slice(before).filter(call => /FROM monitors|FROM check_history/i.test(call.sql));
          assert.equal(calls.length, 2, '沿用一次成员查询和一次批量历史查询');
          assert.deepEqual(calls[1].values, ids);
          assert(result.every((row: any) => row.statusBar24h.length === 24 &&
            row.statusBar24h.every((hour: any) => hour.segments.length === 12)));
          const lastStatus = (id: number) => result.find((row: any) => row.monitorId === id).statusBar24h[23].segments[11];
          assert.equal(lastStatus(1), 'up');
          assert.equal(lastStatus(2), 'warning');
          assert.equal(lastStatus(4), 'down');
          assert.equal(lastStatus(5), null);
        }
      }
      if (scenario === 'normal') {
        assert(applicationTimers.some(timer => timer.delay === 30000));
        assert(queries.some(sql => /^CREATE TABLE/i.test(sql.trim())));
        const saved = await request('/api/groups', 'POST', {name: 'New fixture group'});
        assert.equal(saved.status, 200, await saved.text());
        assert(queries.some(sql => /^INSERT INTO monitor_groups/i.test(sql)));
      } else {
        const source = ['server/server.ts', 'server/routes/groups.ts', 'server/routes/settings.ts',
          'server/routes/communications.ts'].map(file => fs.readFileSync(file, 'utf8')).join('\n');
        const routes = [...source.matchAll(/app\.(post|put|patch|delete)\('([^']+)'/g)]
          .map(match => [match[1].toUpperCase(), match[2].replace(/:[A-Za-z]+/g, '1')])
          .filter(([, route]) => !route.startsWith('/api/auth/') && route !== '/api/content/preview');
        routes.push(['PATCH', '/api/future-feature']);
        for (const [method, route] of routes) {
          const previous = queries.length;
          const response = await request(route, method, {});
          assert.equal(response.status, 403, route);
          assert.deepEqual(await response.json(), {error: 'UI 开发模式下禁止修改或执行操作', code: 'UI_DEV_READ_ONLY'});
          assert.equal(queries.length, previous, '拦截应在业务查询之前');
        }
        assert.equal(applicationTimers.length, 0);
        // 推进到次日，确认没有任何已注册的应用任务可执行。
        for (const timer of applicationTimers.filter(timer => timer.delay <= 86400000)) await timer.callback(...timer.args);
        assert(queries.every(sql => /^(SELECT|SHOW)\b/i.test(sql.trim())));
      }
      const logout = await request('/api/auth/logout', 'POST');
      assert.equal(logout.status, 200);
      console.log(`SCENARIO PASSED: ${scenario}`);
    }
  }
  if (expectedError[scenario]) console.log(`SCENARIO PASSED: ${scenario}`);
} finally {
  Date.now = originalNow;
  globalThis.setInterval = realInterval;
  globalThis.setTimeout = realTimeout;
  if (server) await new Promise<void>(resolve => server!.close(() => resolve()));
  if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
  fs.rmdirSync(testDirectory);
}
