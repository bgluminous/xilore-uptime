import assert from 'node:assert/strict';
import test from 'node:test';
import {once} from 'node:events';
import express from 'express';
import {communicationDb} from './fixtures/communications-db.js';
import {registerCommunicationRoutes} from '../server/routes/communications.js';
import {createDatabaseClient} from '../server/core/db-utils.js';
import {initializeCommunicationTables} from '../server/core/database.js';
import {renderContent, contentId} from '../server/features/content.js';
import {calculateMaintenancePolicy, maintenancePhase, syncMonitorMaintenance, decorateMaintenance,
  loadOverviewStats, loadMaintenanceIntervals, reconcileMaintenancePhases} from '../server/features/maintenance.js';
import {createMaintenanceCoordinator} from '../server/features/maintenance.js';
import {createMonitorRunner} from '../server/features/monitor-runner.js';
import {enqueueContentEvent, enqueueMaintenanceRecheck, processContentDeliveries} from '../server/features/content-notifications.js';
import {registerPublicRoutes} from '../server/routes/public.js';
import {calculateResponseStats, loadResponseStats24h} from '../server/features/response-stats.js';
import {buildHistoryChart} from '../server/features/history-chart.js';
import {buildStatusBars24h} from '../server/features/status-bars.js';

import {initializeRuntimeMode} from '../server/core/runtime-mode.js';
initializeRuntimeMode(false);

const logger = {info() {}, warn() {}, error() {}};
const start = Date.now();
const windowRow = (extra = {}) => ({id: 1, title: '内部维护', body: '内部信息', starts_ms: start,
  ends_ms: start + 1000, cancelled_ms: null, continue_checks: 1, suppress_alerts: 1, exclude_stats: 1,
  is_public: 0, channels: '[]', revision: 1, phase: 'scheduled', created_ms: start, updated_ms: start, ...extra}) as any;
async function addWindow(db: any, options: any = {}, ids = [1]) {
  const row = windowRow(options);
  const keys = Object.keys(row);
  await db.execute(`INSERT INTO maintenances (${keys.join(',')}) VALUES (${keys.map(() => '?')})`, Object.values(row));
  for (const id of ids) await db.execute('INSERT INTO maintenance_monitors VALUES (?, ?)', [row.id, id]);
  return row;
}

test('Markdown 关闭 HTML、危险协议和图片，保持安全链接与代码', () => {
  const html = renderContent('<img src=x onerror=alert(1)>\n\n[x](javascript:alert(1)) [x](data:text/html,test) [x](file:///etc/passwd)\n\n[safe](https://example.com) [mail](mailto:a@example.com)\n\n`<script>`');
  assert(!/<img|<script|href="(?:javascript|data|file):/.test(html));
  assert.match(html, /href="https:\/\/example.com"/);
  assert.match(html, /href="mailto:/);
  assert.match(html, /&lt;img/);
  for (const value of [true, null, {}, 0, -1, '1e1']) assert.throws(() => contentId(value));
});

test('边界含开始不含结束，无期限、取消和全部开关组合，重叠限制独立解除', () => {
  assert.equal(maintenancePhase(windowRow(), start - 1), 'scheduled');
  assert.equal(maintenancePhase(windowRow(), start), 'active');
  assert.equal(maintenancePhase(windowRow(), start + 1000), 'completed');
  assert.equal(maintenancePhase(windowRow({ends_ms: null}), start + 999999), 'active');
  assert.equal(maintenancePhase(windowRow({cancelled_ms: start - 1}), start), 'cancelled');
  for (let mask = 0; mask < 8; mask++) {
    const row = windowRow({continue_checks: mask & 1, suppress_alerts: (mask >> 1) & 1, exclude_stats: (mask >> 2) & 1});
    assert.deepEqual(calculateMaintenancePolicy([row], start), {active: true,
      continueChecks: !!(mask & 1), suppressAlerts: !!(mask & 2), excludeStats: !!(mask & 4)});
  }
  const windows = [windowRow({ends_ms: start + 10, continue_checks: 0, suppress_alerts: 0, exclude_stats: 0}),
    windowRow({ends_ms: start + 20, suppress_alerts: 1, exclude_stats: 0}),
    windowRow({ends_ms: start + 30, suppress_alerts: 0, exclude_stats: 1})];
  assert.deepEqual(calculateMaintenancePolicy(windows, start + 10), {active: true, continueChecks: true, suppressAlerts: true, excludeStats: true});
  assert.deepEqual(calculateMaintenancePolicy(windows, start + 20), {active: true, continueChecks: true, suppressAlerts: false, excludeStats: true});
  assert.deepEqual(calculateMaintenancePolicy(windows, start + 30), {active: false, continueChecks: true, suppressAlerts: false, excludeStats: false});
});

test('受控事务提交、回滚、释放连接，拒绝泄漏执行器和事务控制 SQL', async () => {
  const events: string[] = [];
  const connection = {execute: async (sql: string) => {events.push(sql); return [[], []];},
    beginTransaction: async () => {events.push('begin');}, commit: async () => {events.push('commit');},
    rollback: async () => {events.push('rollback');}, release: () => {events.push('release');}};
  const client = createDatabaseClient({getConnection: async () => connection} as any, false);
  let leaked: any;
  assert.equal(await client.transaction(async tx => {leaked = tx; await tx.execute('SELECT 1'); return 42;}), 42);
  assert.deepEqual(events, ['begin', 'SELECT 1', 'commit', 'release']);
  assert.deepEqual(Object.keys(leaked), ['execute']);
  await assert.rejects(leaked.execute('SELECT 1'), /事务已经结束/);
  await assert.rejects(client.transaction(tx => tx.execute('COMMIT')), /只允许/);
  assert.deepEqual(events.slice(-3), ['begin', 'rollback', 'release']);
  const broken = createDatabaseClient({getConnection: async () => ({...connection,
    rollback: async () => {throw new Error('connection lost');}, destroy: () => events.push('destroy')})} as any, false);
  await assert.rejects(broken.transaction(async () => {throw new Error('original failure');}), /original failure/);
  assert.equal(events.at(-1), 'destroy');
});

test('检测执行覆盖三个开关的八种组合，停止时不产生虚假样本', async () => {
  for (let mask = 0; mask < 8; mask++) {
    const {db} = communicationDb();
    try {
      await addWindow(db, {continue_checks: mask & 1, suppress_alerts: (mask >> 1) & 1, exclude_stats: (mask >> 2) & 1});
      let checks = 0, alerts = 0;
      const runner = createMonitorRunner({getPool: () => db, logger, now: () => start,
        check: async () => {checks++; return {status: 'down', responseTime: 12, message: 'synthetic'};},
        notify: () => {alerts++;}});
      const result = await runner({id: 1, name: 'test', target: '', type: 'http'});
      const [history] = await db.execute('SELECT * FROM check_history');
      assert.equal(checks, mask & 1);
      assert.equal(history.length, mask & 1);
      assert.equal(alerts, (mask & 1) && !(mask & 2) ? 1 : 0);
      if (mask & 1) assert.deepEqual([history[0].in_maintenance, history[0].stats_excluded], [1, (mask >> 2) & 1]);
      else assert.equal(result.skipped, true);
    } finally {await db.end();}
  }
});

test('协调器启停、到期转换及多个首检并行，慢检测不会阻塞五秒周期', async () => {
  const {db, calls} = communicationDb();
  let now = start;
  const checked: number[] = [], errors: string[] = [];
  let release!: () => void;
  const pending = new Promise<void>(resolve => {release = resolve;});
  const coordinator = createMaintenanceCoordinator({getPool: () => db, now: () => now,
    check: async monitor => {checked.push(monitor.id); await pending;}, logger: {error: message => errors.push(message)}});
  try {
    await addWindow(db, {phase: 'scheduled'}, [1, 3, 4]);
    coordinator.start(); await coordinator.tick();
    assert.equal((await db.execute('SELECT phase FROM maintenances'))[0][0].phase, 'active');
    assert.equal(checked.length, 0);
    now += 1000; await coordinator.tick();
    assert.equal((await db.execute('SELECT phase FROM maintenances'))[0][0].phase, 'completed');
    assert.deepEqual(checked, [1, 3]);
    await coordinator.tick(); assert.deepEqual(checked, [1, 3]);
    release(); await coordinator.stop();
    const before = calls.length; await coordinator.tick(); assert.equal(calls.length, before);
    assert.deepEqual(errors, []);
  } finally {release(); await coordinator.stop(); await db.end();}
});

test('通知租约重启恢复，已发送不重复，新静默期阻止旧首检通知', async () => {
  const {db} = communicationDb();
  try {
    const monitor: any = {id: 1, name: '公开 API', type: 'http', target: 'https://example.invalid', email_notification: 1};
    const event: any = {type: 'status', monitor, oldStatus: 'down', newStatus: 'down', force: true, timestamp: new Date(start)};
    await enqueueMaintenanceRecheck(db, event, 10, start);
    await enqueueMaintenanceRecheck(db, event, 10, start);
    await db.execute("UPDATE content_deliveries SET state = 'sending', attempts = 1, lease_until_ms = ?", [start + 100]);
    let sent = 0;
    await processContentDeliveries(db, start, async () => {sent++;}, () => start);
    assert.equal(sent, 0);
    await processContentDeliveries(db, start + 100, async () => {sent++;}, () => start + 100);
    await processContentDeliveries(db, start + 100, async () => {sent++;}, () => start + 100);
    assert.equal(sent, 1);
    await enqueueMaintenanceRecheck(db, event, 11, start);
    await addWindow(db);
    await processContentDeliveries(db, start, async () => {assert.fail('静默期间不得发送');}, () => start);
    assert.equal((await db.execute("SELECT state FROM content_deliveries WHERE event_key LIKE '%:11:%'"))[0][0].state, 'skipped');
    await enqueueMaintenanceRecheck(db, event, 10, start + 1000);
    await processContentDeliveries(db, start + 1000, async () => {sent++;}, () => start + 1000);
    assert.equal(sent, 2, '清空历史后复用编号不会丢掉新的首检通知');
  } finally {await db.end();}
});

test('增量迁移可重复执行，已有历史不被改写，失败向上传播', async () => {
  const tables = new Set<string>(), columns = new Set<string>(), alters: string[] = [];
  const db: any = {async execute(sql: string) {
    if (sql.startsWith('CREATE TABLE IF NOT EXISTS')) {tables.add(sql.split(' ')[5]); return [[], []];}
    const column = sql.match(/LIKE '(\w+)'/)?.[1];
    if (column) return [columns.has(column) ? [{Field: column}] : [], []];
    if (sql.startsWith('ALTER TABLE')) {columns.add(sql.split(' ')[5]); alters.push(sql); return [[], []];}
    throw new Error('Unexpected SQL');
  }};
  await initializeCommunicationTables(db); await initializeCommunicationTables(db);
  assert.equal(tables.size, 5); assert.equal(alters.length, 2);
  assert.deepEqual([...columns], ['in_maintenance', 'stats_excluded']);
  await assert.rejects(initializeCommunicationTables({execute: async () => {throw new Error('denied');}} as any), /denied/);
});

test('检测统一拦截；真实样本冻结标记；恢复后只发一次，暂停状态保留', async () => {
  const {db} = communicationDb();
  try {
    await addWindow(db, {continue_checks: 0}, [1, 4]);
    await db.execute('UPDATE monitors SET email_notification = 1 WHERE id = 1');
    let time = start, calls = 0, resultStatus = 'down';
    const sent: any[] = [];
    const context: any = {getPool: () => db, logger, now: () => time,
      check: async () => {calls++; return {status: resultStatus, responseTime: 0, message: '合成检测'};},
      notify: (_: any, event: any) => sent.push(event)};
    let runner = createMonitorRunner(context);
    assert.equal((await runner({id: 1, name: 'test'})).skipped, true);
    assert.equal(calls, 0); assert.equal((await db.execute('SELECT * FROM check_history'))[0].length, 0);
    await db.execute('UPDATE maintenances SET continue_checks = 1 WHERE id = 1');
    await runner({id: 1, name: 'test'});
    const [history] = await db.execute('SELECT * FROM check_history');
    assert.deepEqual([history[0].status, history[0].response_time, history[0].in_maintenance, history[0].stats_excluded], ['down', 0, 1, 1]);
    assert.equal(sent.length, 0);
    await db.execute('UPDATE maintenances SET body = ?, ends_ms = ? WHERE id = 1', ['新说明', start + 2000]);
    assert.deepEqual((await db.execute('SELECT * FROM check_history'))[0], history);
    time = start + 2000;
    runner = createMonitorRunner(context); // 模拟重启，只重用持久化数据。
    await runner({id: 1, name: 'test'});
    await processContentDeliveries(db, time, async (_, channel, event) => {sent.push(event.monitor_event);}, () => time);
    await runner({id: 1, name: 'test'});
    assert.equal(sent.filter(event => event.force).length, 1);
    assert.equal(sent[0].newStatus, 'down');
    assert.equal((await db.execute('SELECT enabled FROM monitors WHERE id = 4'))[0][0].enabled, 0);
  } finally {await db.end();}
});

test('静默结束正常时仅向维护前异常的服务发送恢复；跨过整个预约也安排首检', async () => {
  for (const before of ['up', 'down', 'warning']) {
    const {db} = communicationDb();
    try {
      await db.execute('UPDATE monitors SET status = ?, last_check = ? WHERE id = 1', [before === 'warning' ? 'up' : before, start - 100]);
      await db.execute('INSERT INTO check_history (monitor_id, status, checked_at) VALUES (1, ?, ?)', [before, start - 100]);
      await db.execute('UPDATE monitors SET email_notification = 1 WHERE id = 1');
      await addWindow(db);
      await db.transaction(tx => syncMonitorMaintenance(tx, 1, start - 1));
      // 下一次进程运行时维护已经结束，不依赖协调器曾看到 active。
      const sent: any[] = [];
      const runner = createMonitorRunner({getPool: () => db, logger: logger as any, now: () => start + 1000,
        check: async () => ({status: 'up', responseTime: 8, message: '恢复'}), notify: (_: any, event: any) => {sent.push(event);}});
      await runner({id: 1, name: 'test'});
      assert.equal(sent.length, 0, '首检通知必须先持久化');
      await processContentDeliveries(db, start + 1000, async (_, channel, event) => {sent.push(event.monitor_event);}, () => start + 1000);
      assert.equal(sent.length, before === 'up' ? 0 : 1);
      if (sent.length) assert.equal(sent[0].force, true);
      assert.equal((await db.execute('SELECT recheck_pending FROM maintenance_runtime'))[0][0].recheck_pending, 0);
    } finally {await db.end();}
  }
});

test('统计统一排除，原始历史保留，停止检测也显示区间，公开服务仅通用维护标识', async () => {
  const {db} = communicationDb();
  try {
    await addWindow(db, {starts_ms: start - 3600000, ends_ms: null, continue_checks: 0}, [1, 2]);
    await db.execute('INSERT INTO check_history (monitor_id, status, response_time, checked_at, in_maintenance, stats_excluded) VALUES (1, ?, ?, ?, 1, 1)', ['down', 9999, start - 100]);
    const [monitors] = await db.execute('SELECT * FROM monitors WHERE id = 1');
    const [safe] = await decorateMaintenance(db, monitors, true, start);
    assert.equal(safe.effective_status, 'maintenance'); assert.equal(safe.status, 'up');
    assert.deepEqual(safe.maintenance, {active: true, items: []});
    assert.equal((await loadOverviewStats(db, true, start)).avgUptime24h, null);
    assert.equal((await loadOverviewStats(db, true, start)).maintenance, 1);
    assert.deepEqual((await loadResponseStats24h(db, [1], start)).get(1), {avgResponse: null, p99Response: null});
    const [history] = await db.execute('SELECT * FROM check_history');
    assert.deepEqual(calculateResponseStats(history), {avgResponse: null, p99Response: null});
    const intervals = await loadMaintenanceIntervals(db, [1], start - 86400000, start);
    const bars = buildStatusBars24h([1], history, intervals, start)[0].statusBar24h;
    assert.equal(bars.at(-1).uptime, null); assert.equal(bars.at(-1).excludedChecks, 1);
    assert(bars.at(-1).segments.every((segment: string) => segment === 'maintenance'));
    const chart = buildHistoryChart(history, {hours: 1, chartPoints: 60}, 60, start, intervals);
    assert(chart.every(point => point.in_maintenance && point.response_time === null));
    assert.equal(chart.reduce((count, point) => count + point.count, 0), 1);
    assert.equal(chart.at(-1)?.status, 'down');
  } finally {await db.end();}
});

test('通知按事件和渠道去重，失败三次重试，不补过期开始，普通改动不影响待投递快照', async () => {
  const {db} = communicationDb();
  try {
    const row = await addWindow(db, {channels: '["email","webhook"]'});
    await reconcileMaintenancePhases(db, start + 1001);
    const [initial] = await db.execute('SELECT * FROM content_deliveries');
    assert.equal(initial.length, 2);
    assert(initial.every((item: any) => JSON.parse(item.payload).event === 'maintenance_completed'));
    await db.transaction(async tx => {await enqueueContentEvent(tx, 'maintenance', row, 'maintenance_started', start);
      await enqueueContentEvent(tx, 'maintenance', row, 'maintenance_started', start);});
    assert.equal((await db.execute('SELECT * FROM content_deliveries'))[0].length, 4);
    let now = start + 1001, sent = 0;
    const failed = async () => {sent++; throw new Error('synthetic only');};
    for (const delay of [0, 30000, 120000, 300000, 999999]) {
      now += delay; await processContentDeliveries(db, now, failed, () => now);
    }
    assert.equal(sent, 8);
    const [rows] = await db.execute('SELECT * FROM content_deliveries');
    assert.equal(rows.filter((row: any) => row.state === 'failed' && row.attempts === 4).length, 2);
    assert.equal(rows.filter((row: any) => row.state === 'skipped').length, 2);
    await enqueueContentEvent(db, 'maintenance', {...row, revision: 2}, 'maintenance_rescheduled', now);
    const received: any[] = [];
    await processContentDeliveries(db, now, async (_, channel, payload) => {received.push({channel, payload});}, () => now);
    await processContentDeliveries(db, now, async () => {assert.fail('duplicate');}, () => now);
    assert.equal(received.length, 2); assert.equal(received[0].payload.body, row.body);
  } finally {await db.end();}
});

test('公开合并时间线统一排序和跨类型分页，历史按归档或结束时间排列，保留隐私与边界', async () => {
  const {db} = communicationDb();
  const app = express();
  registerCommunicationRoutes(app, {getPool: () => db, logger, now: () => start,
    authMiddleware: (_, res) => {res.status(401).end();}});
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = `http://127.0.0.1:${(server.address() as any).port}/api/public/updates`;
  try {
    assert.equal((await (await fetch(base)).json()).total, 0);
    for (let id = 1; id <= 25; id++) {
      await db.execute(`INSERT INTO announcements (id, title, body, state, pinned, published_ms, created_ms, updated_ms)
        VALUES (?, ?, ?, 'published', ?, ?, ?, ?)`, [id, `公告 ${id}`, '**公开说明**', Number(id === 25), start - id * 2000, start, start]);
      await addWindow(db, {id, title: `维护 ${id}`, body: '**公开维护**', is_public: 1,
        starts_ms: start - id * 2000 + 1000, ends_ms: null}, [1, 2]);
    }
    await addWindow(db, {id: 26, ends_ms: null, title: '内部维护秘密'});
    await addWindow(db, {id: 27, ends_ms: null, is_public: 1, title: '只有私有监控'}, [2]);
    await addWindow(db, {id: 28, is_public: 1, starts_ms: start - 40000, ends_ms: start - 30000});
    await addWindow(db, {id: 29, is_public: 1, starts_ms: start + 40000, cancelled_ms: start - 10000});
    await addWindow(db, {id: 30, is_public: 1, starts_ms: start - 1000, ends_ms: start});
    await db.execute(`INSERT INTO announcements (id, title, body, state, pinned, published_ms, created_ms, updated_ms)
      VALUES (99, '归档公告', '', 'archived', 1, ?, ?, ?)`, [start - 100000, start - 100000, start - 5000]);
    await db.execute("INSERT INTO announcements (id, title, body) VALUES (100, '草稿秘密', '')");
    const pages = await Promise.all([1, 2, 3].map(async page => {
      const response = await fetch(`${base}?page=${page}`);
      assert.equal(response.status, 200);
      return response.json();
    }));
    assert.deepEqual(pages.map(page => [page.items.length, page.has_more]), [[20, true], [20, true], [10, false]]);
    assert.deepEqual(pages.map(page => page.total), [50, 50, 50]);
    const items = pages.flatMap(page => page.items);
    const keys = items.map(row => `${row.kind}-${row.id}`);
    assert.equal(new Set(keys).size, 50);
    assert.equal(keys[0], 'announcements-25');
    const unpinned = items.slice(1).map(row => Date.parse(row.timeline_at));
    assert.deepEqual(unpinned, [...unpinned].sort((a, b) => b - a));
    assert(items.filter(row => row.kind === 'maintenances').every(row => row.monitors.length === 1 && row.monitors[0].id === 1));
    assert(items.every(row => !('channels' in row) && !('body' in row) && !('target' in row)));
    assert(!/秘密|私有|example\.invalid/.test(JSON.stringify(items)));
    const history = await (await fetch(`${base}?history=1`)).json();
    assert.equal(history.total, 4);
    assert.deepEqual(history.items.map(row => `${row.kind}-${row.id}`),
      ['maintenances-30', 'announcements-99', 'maintenances-29', 'maintenances-28']);
    assert.equal((await fetch(`${base}?page=0`)).status, 400);
  } finally {await new Promise<void>(resolve => server.close(() => resolve())); await db.end();}
});

test('真实 HTTP 公告生命周期、管理员权限、维护锁定与公开边界、原子回滚', async () => {
  const {db} = communicationDb();
  let now = start;
  const app = express(); app.use(express.json());
  const auth: express.RequestHandler = (req, res, next) => {
    const role = req.headers['x-test-role'];
    if (!role) {res.status(401).end(); return;}
    req.user = {id: 1, username: 'synthetic', role: String(role)}; next();
  };
  registerCommunicationRoutes(app, {getPool: () => db, logger, now: () => now, authMiddleware: auth});
  registerPublicRoutes(app, {getPool: () => db, logger});
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const request = async (path: string, method = 'GET', body?: object, role = 'admin') => {
    const response = await fetch(base + '/api/' + path, {method, headers: {'Content-Type': 'application/json', ...(role ? {'x-test-role': role} : {})}, body: body ? JSON.stringify(body) : undefined});
    return {status: response.status, data: response.status === 401 ? null : await response.json()};
  };
  try {
    assert.equal((await request('announcements', 'GET', undefined, '')).status, 401);
    assert.equal((await request('maintenances', 'POST', {}, 'viewer')).status, 403);
    assert.equal((await request('content/preview', 'POST', {body: '<script>alert(1)</script>'}, '')).status, 401);
    assert.equal((await request('content/preview', 'POST', {body: '**安全**'})).data.html.trim(), '<p><strong>安全</strong></p>');
    let result = await request('announcements', 'POST', {title: '草稿秘密', body: '正文', channels: ['email']});
    const id = result.data.id;
    assert.equal(result.status, 201);
    assert.equal((await request('public/announcements')).data.items.length, 0);
    await request(`announcements/${id}/publish`, 'POST', {revision: 1});
    await request(`announcements/${id}`, 'PUT', {revision: 2, title: '全站公告', pinned: true});
    assert.equal((await request('public/announcements')).data.items[0].pinned, true);
    assert.equal((await db.execute('SELECT * FROM content_deliveries'))[0].length, 1);
    assert.equal((await request(`announcements/${id}/withdraw`, 'POST', {revision: 1})).status, 409);
    await request(`announcements/${id}/withdraw`, 'POST', {revision: 3});
    assert.equal((await request('public/announcements')).data.items.length, 0);
    await request(`announcements/${id}/publish`, 'POST', {revision: 4});
    await request(`announcements/${id}/archive`, 'POST', {revision: 5});
    assert.equal((await request('public/announcements?history=1')).data.items[0].state, 'archived');
    assert.equal((await request('public/announcements')).data.items.length, 0);
    result = await request('maintenances', 'POST', {title: '内部秘密说明', body: '内部目标地址', immediate: true, monitor_ids: [1, 2]});
    const maintenanceId = result.data.id; assert.equal(result.status, 201);
    assert.equal((await request('public/maintenances')).data.items.length, 0);
    result = await request(`maintenances/${maintenanceId}`, 'PUT', {revision: 1, continue_checks: false});
    assert.equal(result.status, 409);
    result = await request(`maintenances/${maintenanceId}`, 'PUT', {revision: 1, title: '公开维护', body: '公开说明', is_public: true, ends_at: new Date(now + 10000).toISOString()});
    assert.equal(result.status, 200);
    const publicRow = (await request('public/maintenances')).data.items[0];
    assert.deepEqual(publicRow.monitors, [{id: 1, name: '公开 API'}]);
    assert(!JSON.stringify(publicRow).includes('私有')); assert(!('channels' in publicRow)); assert(!('body' in publicRow));
    await db.execute('INSERT INTO check_history (monitor_id, status, message, checked_at) VALUES (1, ?, ?, ?)',
      ['down', '连接失败 private.example.invalid:5432', start - 100]);
    const publicBars = (await request('public/monitors/statusbars')).data;
    assert(!JSON.stringify(publicBars).includes('private.example.invalid'));
    // 分组增加成员不会扩大快照范围。
    await db.execute('UPDATE monitors SET group_id = 1 WHERE id = 3');
    assert.equal((await db.execute('SELECT * FROM maintenance_monitors WHERE maintenance_id = ?', [maintenanceId]))[0].length, 2);
    now += 5000;
    assert.equal((await request(`maintenances/${maintenanceId}/finish`, 'POST', {revision: 2})).status, 200);
    assert.equal((await request('public/maintenances?history=1')).data.items[0].state, 'completed');
    assert.equal((await request('maintenances', 'POST', {title: '非法预约', monitor_ids: [1], starts_at: new Date(now + 1000).toISOString()})).status, 400);
    result = await request('maintenances', 'POST', {title: '预约', monitor_ids: [1], channels: ['webhook'], starts_at: new Date(now + 1000).toISOString(), ends_at: new Date(now + 2000).toISOString()});
    assert.equal(result.status, 201);
    assert.equal((await request(`maintenances/${result.data.id}/cancel`, 'POST', {revision: 1})).status, 200);
    const before = (await db.execute('SELECT * FROM maintenances'))[0].length;
    assert.equal((await request('maintenances', 'POST', {title: '不存在', immediate: true, monitor_ids: [1, 999]})).status, 400);
    assert.equal((await db.execute('SELECT * FROM maintenances'))[0].length, before);
    await assert.rejects(db.transaction(async tx => {
      await tx.execute('INSERT INTO announcements (title) VALUES (?)', ['rollback']);
      await enqueueContentEvent(tx, 'announcement', {id: 900, title: 'rollback', body: '', channels: '["email"]', revision: 1}, 'announcement_published', now);
      throw new Error('rollback');
    }));
    assert.equal((await db.execute('SELECT * FROM announcements WHERE title = ?', ['rollback']))[0].length, 0);
    assert.equal((await db.execute('SELECT * FROM content_deliveries WHERE owner_id = 900'))[0].length, 0);
    for (let i = 0; i < 22; i++) {
      await request('announcements', 'POST', {title: `分页 ${i}`, publish: true});
    }
    const first = (await request('public/announcements')).data;
    const second = (await request('public/announcements?page=2')).data;
    assert.deepEqual([first.items.length, first.has_more, second.items.length, second.has_more], [20, true, 2, false]);
    assert.equal(new Set([...first.items, ...second.items].map(row => row.id)).size, 22);
  } finally {await new Promise<void>(resolve => server.close(() => resolve())); await db.end();}
});
