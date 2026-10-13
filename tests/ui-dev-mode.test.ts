import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import { assertReadOnlySql, createDatabaseClient } from '../server/core/db-utils.js';
import { initializeTables, testDatabaseConnection } from '../server/core/database.js';
import { initializeRuntimeMode, resolveUiDevMode, UiDevReadOnlyError, uiDevModeMiddleware } from '../server/core/runtime-mode.js';
import { singleCheck } from '../server/features/monitor-checks.js';
import { dispatchMonitorNotification, sendFeishuRequest } from '../server/features/notifications.js';
import {initializeCommunicationTables} from '../server/core/database.js';
import {createMaintenanceCoordinator, reconcileMaintenancePhases} from '../server/features/maintenance.js';
import {createMonitorRunner} from '../server/features/monitor-runner.js';
import {enqueueContentEvent, processContentDeliveries, sendContentNotification} from '../server/features/content-notifications.js';

let passed = 0;
async function test(name: string, run: () => void | Promise<void>) {
  await run();
  console.log(`✓ ${name}`);
  passed++;
}

await test('配置默认值、布尔校验与环境变量优先级', () => {
  assert.equal(resolveUiDevMode(undefined), false);
  assert.equal(resolveUiDevMode(true), true);
  assert.equal(resolveUiDevMode(false), false);
  for (const value of ['true', '1']) assert.equal(resolveUiDevMode(false, value), true);
  for (const value of ['false', '0']) assert.equal(resolveUiDevMode(true, value), false);
  for (const value of ['TRUE', 'yes', '', ' false ', '2']) assert.throws(() => resolveUiDevMode(false, value));
  for (const value of ['false', 0, null, {}]) assert.throws(() => resolveUiDevMode(value));
});

await test('SQL 查询放行，写入、DDL、事务、锁、导出和注释绕过被阻止', () => {
  for (const sql of ['SELECT 1', ' \nselect id FROM monitors WHERE id = ?', 'SELECT COUNT(*) FROM users',
    "SELECT 'FOR UPDATE' as message", "SHOW COLUMNS FROM monitors LIKE 'retries'", "SHOW TABLES LIKE 'users'"]) {
    assert.doesNotThrow(() => assertReadOnlySql(sql));
  }
  for (const sql of ['INSERT INTO settings VALUES (?)', 'UPDATE monitors SET enabled=0', 'DELETE FROM check_history',
    'REPLACE INTO settings VALUES (?)', 'TRUNCATE TABLE check_history', 'CREATE DATABASE test', 'ALTER TABLE users ADD x INT',
    'DROP TABLE monitors', 'CALL task()', 'SET SESSION TRANSACTION READ WRITE', 'START TRANSACTION', 'COMMIT',
    'SELECT 1; DELETE FROM users', '/* hi */ SELECT 1', 'SELECT /*!50000 1 */', 'SELECT 1 -- comment', 'SELECT 1 # comment',
    'SELECT * FROM users FOR UPDATE', 'SELECT * FROM users FOR SHARE', 'SELECT * FROM users LOCK IN SHARE MODE',
    "SELECT 1 INTO OUTFILE '/tmp/file'", "SELECT 1 INTO DUMPFILE '/tmp/file'", "SELECT GET_LOCK('lock', 0)",
    "SELECT `GET_LOCK`('lock', 0)", "SELECT \"GET_LOCK\"('lock', 0)", "SHOW COLUMNS FROM users WHERE GET_LOCK('lock', 0)",
    'SELECT SLEEP(30)', 'WITH x AS (SELECT 1) DELETE FROM users', 'SHOW PROCEDURE STATUS']) {
    assert.throws(() => assertReadOnlySql(sql), (error: any) => error.code === 'UI_DEV_READ_ONLY' && error.status === 403, sql);
  }
});

await test('连接重用和新连接均先设置会话只读，不暴露原始连接', async () => {
  const calls: string[] = [];
  const connection = {
    query: async (sql: string) => { calls.push(sql); },
    execute: async (sql: string, values: any[]) => { calls.push(sql); return [[{values}], []]; },
    release: () => calls.push('release'), destroy: () => calls.push('destroy')
  };
  let count = 0;
  const raw: any = {getConnection: async () => { count++; return count < 3 ? connection : {...connection}; }, end: async () => { calls.push('end'); }};
  const client = createDatabaseClient(raw, true);
  assert.deepEqual(Object.keys(client).sort(), ['end', 'execute', 'transaction']);
  assert.equal(Object.isFrozen(client), true);
  await assert.rejects(client.transaction(async () => { throw new Error('must not run'); }), UiDevReadOnlyError);
  await client.execute('SELECT 1', ['UPDATE users SET password = ?']);
  await client.execute('SELECT 2');
  await client.execute('SELECT 3');
  assert.deepEqual(calls, [1, 2, 3].flatMap(id => ['SET SESSION TRANSACTION READ ONLY', `SELECT ${id}`, 'release']));
  await assert.rejects(client.execute('DELETE FROM users'), UiDevReadOnlyError);
  assert.equal(count, 3, '写 SQL 应在申请连接之前被拒绝');
  await client.end();
  assert.equal(calls.at(-1), 'end');
});

await test('保护设置失败销毁连接，查询失败释放连接', async () => {
  let queried = false, destroyed = false, released = false;
  const connection: any = {query: async () => {throw new Error('protection failed');},
    execute: async () => {queried = true; throw new Error('query failed');},
    destroy: () => {destroyed = true;}, release: () => {released = true;}};
  const client = createDatabaseClient({getConnection: async () => connection} as any, true);
  await assert.rejects(client.execute('SELECT 1'), /protection failed/);
  assert.deepEqual([queried, destroyed, released], [false, true, false]);
  connection.query = async () => {};
  destroyed = false;
  await assert.rejects(client.execute('SELECT 1'), /query failed/);
  assert.deepEqual([queried, destroyed, released], [true, false, true]);
});

await test('普通模式允许原有 SQL，不设置只读会话', async () => {
  let received: unknown[];
  const client = createDatabaseClient({execute: async (...args: unknown[]) => {received = args; return [{affectedRows: 1}, []];}} as any, false);
  await client.execute('UPDATE settings SET value = ?', ['value']);
  assert.deepEqual(received!, ['UPDATE settings SET value = ?', ['value']]);
});

initializeRuntimeMode(true);
await test('副作用入口独立拒绝检测、通知、迁移和安装连接测试', async () => {
  await assert.rejects(singleCheck(null!, null!), UiDevReadOnlyError);
  assert.throws(() => dispatchMonitorNotification(null!, null!), UiDevReadOnlyError);
  await assert.rejects(sendFeishuRequest('https://invalid.test', null, {}, {}), UiDevReadOnlyError);
  await assert.rejects(initializeTables(null!), UiDevReadOnlyError);
  await assert.rejects(testDatabaseConnection(null!), UiDevReadOnlyError);
  await assert.rejects(initializeCommunicationTables(null!), UiDevReadOnlyError);
  await assert.rejects(reconcileMaintenancePhases(null!, Date.now()), UiDevReadOnlyError);
  await assert.rejects(enqueueContentEvent(null!, 'announcement', null!, '', Date.now()), UiDevReadOnlyError);
  await assert.rejects(processContentDeliveries(null!), UiDevReadOnlyError);
  await assert.rejects(sendContentNotification(null!, 'email', null!), UiDevReadOnlyError);
  assert.throws(() => createMonitorRunner({getPool() {assert.fail('不得读取连接');}, logger: null!})(null!), UiDevReadOnlyError);
  const coordinator = createMaintenanceCoordinator({getPool() {assert.fail('不得调度');}, check: null!, logger: null!});
  coordinator.start(); await coordinator.tick(); await coordinator.stop();
  assert.throws(() => initializeRuntimeMode(false), /重启/);
});

await test('HTTP 守卫仅放行查询、登录退出和内存预览，新写路由也默认禁止', () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    let status = 0, body: any, called = false;
    uiDevModeMiddleware({method, path: '/api/future-feature'} as any,
      {status(code: number) {status = code; return this;}, json(value: any) {body = value;}} as any, () => {called = true;});
    assert.deepEqual([status, body.code, called], [403, 'UI_DEV_READ_ONLY', false]);
  }
  for (const [method, path] of [['GET', '/api/monitors'], ['HEAD', '/api/monitors'], ['OPTIONS', '/api/monitors'],
    ['POST', '/api/content/preview'], ['POST', '/api/auth/login'], ['POST', '/api/auth/logout/']]) {
    let called = false;
    uiDevModeMiddleware({method, path} as any, {} as any, () => {called = true;});
    assert.equal(called, true);
  }
});

await test('前端函数在模式未确认和只读时均不发请求、不改本地数据', async () => {
  const listeners: any[] = [];
  const context = vm.createContext({
    ui: {theme: {}, runtime: {canWrite: () => false, guardWrite: (event: any) => {event?.preventDefault(); return false;}}},
    document: {addEventListener: (...args: any[]) => listeners.push(args)},
    fetch: () => {throw new Error('不应请求接口');},
    window: {}, console
  });
  vm.runInContext(fs.readFileSync('public/assets/app.js', 'utf8') + '\n globalThis.testApp = app; globalThis.testSetup = setup;', context);
  const app = context.testApp;
  app.groups = [{id: 1, sort_order: 0}, {id: 2, sort_order: 0}];
  const original = JSON.stringify(app.groups);
  await app.normalizeGroupOrder();
  await app.updateGroupOrderFromDOM(1, 1);
  assert.equal(JSON.stringify(app.groups), original);
  for (const method of ['showAddModal', 'editGroupName', 'deleteGroup', 'toggleMonitor', 'deleteMonitor', 'checkNow', 'refreshAll',
    'clearHistory', 'deleteHistoryRecord', 'testEmail', 'testWebhook', 'testFeishu', 'clearCurrentSettingsConfig',
    'clearEmailConfig', 'clearWebhookConfig', 'clearFeishuConfig', 'deleteAllHistory']) await app[method](1);
  for (const method of ['saveMonitor', 'saveSettings', 'addGroup']) {
    let prevented = false;
    await app[method]({preventDefault() {prevented = true;}});
    assert.equal(prevented, true);
  }
  for (const method of ['testDatabase', 'completeSetup', 'completeSetupWithExistingAdmin']) await context.testSetup[method]();
  vm.runInContext(fs.readFileSync('public/assets/setup.js', 'utf8') + '\n globalThis.testStandalone = setupApp;', context);
  for (const method of ['testDatabase', 'completeSetup', 'completeSetupWithExistingAdmin']) await context.testStandalone[method]();
});

await test('共享前端状态加载失败保持只读，成功后按模式恢复，复用同一请求', async () => {
  for (const result of [true, false, null, 'error']) {
    let calls = 0;
    const context = vm.createContext({
      window: {matchMedia: () => ({matches: false, addEventListener() {}})},
      localStorage: {getItem: () => null}, CustomEvent: class {},
      document: {documentElement: {setAttribute() {}}, querySelectorAll: () => [], dispatchEvent() {}, addEventListener() {}},
      fetch: async () => {calls++; if (result === 'error') throw new Error('offline');
        return {ok: true, json: async () => ({installed: true, initialized: true, uiDevMode: result})};},
      console: {error() {}}
    });
    vm.runInContext(fs.readFileSync('public/assets/utils.js', 'utf8') + '\n globalThis.testRuntime = ui.runtime;', context);
    const runtime = context.testRuntime;
    assert.equal(runtime.canWrite(), false);
    const first = runtime.load();
    assert.equal(runtime.load(), first);
    await first;
    assert.equal(calls, 1);
    assert.equal(runtime.canWrite(), result === false);
    assert.equal(runtime.ready, typeof result === 'boolean');
  }
});

for (const scenario of ['readonly', 'normal', 'missing-config', 'bad-json', 'bad-mode', 'no-admin', 'missing-column', 'protection-failure']) {
  await test(`隔离启动及真实 HTTP 路由：${scenario}`, () => {
    const result = spawnSync(process.execPath, ['node_modules/tsx/dist/cli.mjs', 'tests/fixtures/ui-dev-server.ts', scenario],
      {encoding: 'utf8', timeout: 30000, windowsHide: true});
    assert.equal(result.status, 0, result.error?.message || result.stderr || result.stdout);
    assert.match(result.stdout, /SCENARIO PASSED/);
  });
}
console.log(`\n${passed} 项检查通过；未连接真实数据库。`);
