import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {spawnSync} from 'node:child_process';
import {test} from 'node:test';

function loadUi() {
  const nodes = new Map<string, any>();
  const storedCalls: string[] = [];
  const context = vm.createContext({
    window: {matchMedia: () => ({matches: true})},
    document: {getElementById: (id: string) => nodes.get(id) || null, querySelectorAll: () => [],
      addEventListener() {}, activeElement: null},
    localStorage: {getItem(key: string) {storedCalls.push(key); return '["1","2"]';},
      setItem(key: string) {storedCalls.push(key);}},
    Element: class {}, HTMLElement: class {},
    console: {error() {}}, AbortController,
    fetch: async () => {throw new Error('未配置请求');}
  });
  const source = fs.readFileSync('public/assets/utils.js', 'utf8');
  vm.runInContext(source.slice(0, source.lastIndexOf('ui.theme.init();')) + '\nglobalThis.testUi = ui;', context);
  const publicSource = fs.readFileSync('public/assets/status.js', 'utf8');
  vm.runInContext(publicSource.slice(0, publicSource.lastIndexOf('// 初始化')) + '\nglobalThis.testPublic = publicApp;', context);
  vm.runInContext(fs.readFileSync('public/assets/app.js', 'utf8') + '\nglobalThis.testApp = app;', context);
  return {context, nodes, storedCalls, ui: context.testUi, publicApp: context.testPublic, app: context.testApp};
}

const end = Date.parse('2026-10-11T08:00:00Z');
function bars(status: string | null, endMs = end) {
  return Array.from({length: 24}, (_, index) => ({
    startTime: new Date(endMs - (24 - index) * 3600000).toISOString(),
    endTime: new Date(endMs - (23 - index) * 3600000).toISOString(),
    segments: Array(12).fill(status), status
  }));
}
const monitor = (id: number, status: string | null, extra: object = {}) =>
  ({id, name: `服务${id}`, group_id: 1, enabled: 1, status, statusBar24h: bars(status), ...extra});
const plain = (value: unknown) => JSON.parse(JSON.stringify(value));

test('分组逐个五分钟区间取最严重状态，保留正常和无数据数量，不修改输入', () => {
  const {ui} = loadUi();
  const changing = monitor(1, 'up');
  changing.statusBar24h[0].segments[1] = 'warning';
  changing.statusBar24h[0].segments[2] = 'down';
  const members = [changing, monitor(2, 'up'), monitor(3, null), monitor(4, 'down', {enabled: 0})];
  const original = structuredClone(members);
  const result = plain(ui.groupHistory.aggregate(members));
  assert.equal(result.length, 24);
  assert.equal(result[0].segments.length, 12);
  assert.deepEqual(result[0].segments.slice(0, 3), [
    {up: 2, down: 0, warning: 0, unknown: 1, status: 'up'},
    {up: 1, down: 0, warning: 1, unknown: 1, status: 'warning'},
    {up: 1, down: 1, warning: 0, unknown: 1, status: 'down'}
  ]);
  assert.deepEqual(members, original);
  assert.equal(ui.groupHistory.aggregate([monitor(9, null)])[0].segments[0].status, null);
  assert.deepEqual(plain(ui.groupHistory.aggregate([monitor(1, 'down', {enabled: false})])), []);
});

test('跨组与筛选结果隔离，不把不同批次的时间格按下标合并', () => {
  const {ui} = loadUi();
  const members = [monitor(1, 'up'), monitor(2, 'down', {group_id: 2}), monitor(3, 'warning')];
  assert.equal(ui.groupHistory.aggregate(members.filter(item => item.group_id === 2))[0].segments[0].status, 'down');
  assert.equal(ui.groupHistory.aggregate(members.filter(item => item.status === 'up'))[0].segments[0].status, 'up');
  const result = ui.groupHistory.aggregate([monitor(1, 'down'), monitor(2, 'up', {statusBar24h: bars('up', end + 60000)})]);
  assert.equal(result[0].endTime, bars('up', end + 60000)[0].endTime);
  assert.deepEqual(plain(result[0].segments[0]), {up: 1, down: 0, warning: 0, unknown: 1, status: 'up'});
});

test('悬浮精确展示区间及各状态数量；空态、首次失败与保留旧数据有明确提示', () => {
  const {ui} = loadUi();
  const html = ui.groupHistory.render([monitor(1, 'up'), monitor(2, 'down'), monitor(3, null)], 'ready');
  assert.equal((html.match(/class="status-bar-group"/g) || []).length, 24);
  assert.equal((html.match(/class="status-bar-segment /g) || []).length, 288);
  assert.match(html, /离线 1 个 · 波动 0 个 · 正常 1 个 · 无数据 1 个/);
  assert.match(html, /最近 24 小时/);
  assert.match(ui.groupHistory.render([monitor(1, 'up', {statusBar24h: null})]), /status-bar-skeleton-full/);
  assert.match(ui.groupHistory.render([monitor(1, 'up', {statusBar24h: null})], 'error'), /状态记录暂不可用/);
  assert.match(ui.groupHistory.render([monitor(1, 'up')], 'error'), /显示上次成功记录/);
  assert.match(ui.groupHistory.render([], 'ready'), /无参与统计的服务/);
  assert.doesNotMatch(ui.groupHistory.render([], 'ready'), /skeleton/);
});

function section(id: string) {
  const classes = new Set<string>();
  const attributes = new Map<string, string>();
  const label = {textContent: ''};
  const body = {inert: false, toggleAttribute(_name: string, value: boolean) {this.inert = value;}};
  return {attributes, label, body,
    getAttribute: () => id,
    classList: {contains: (name: string) => classes.has(name),
      toggle(name: string, value: boolean) {if (value) classes.add(name); else classes.delete(name);}},
    querySelector: (selector: string) => selector === '.group-body' ? body : selector === '.public-collapse-label' ? label :
      {setAttribute: (name: string, value: string) => attributes.set(name, value)}
  };
}

test('公开页忽略旧存储，仅当前离线或波动默认展开，刷新和新分组遵守本次选择', () => {
  const {publicApp, nodes, storedCalls} = loadUi();
  for (const id of ['public-monitor-list', 'public-expand-all', 'public-collapse-all']) nodes.set(id, {addEventListener() {}});
  publicApp.initGroupControls();
  assert.deepEqual(storedCalls, []);
  assert.equal(publicApp.isGroupCollapsed(1, [monitor(1, 'up')]), true);
  assert.equal(publicApp.isGroupCollapsed(2, [monitor(2, 'down')]), false);
  assert.equal(publicApp.isGroupCollapsed(3, [monitor(3, 'warning')]), false);
  assert.equal(publicApp.isGroupCollapsed(4, [monitor(4, 'unknown')]), true);
  assert.equal(publicApp.isGroupCollapsed(5, [monitor(5, 'down', {enabled: 0})]), true);
  assert.equal(publicApp.isGroupCollapsed(0, [monitor(6, 'up')]), true);
  publicApp.setGroupCollapsed(section('1'), false);
  publicApp.setGroupCollapsed(section('2'), true);
  assert.equal(publicApp.isGroupCollapsed(1, [monitor(1, 'up')]), false);
  assert.equal(publicApp.isGroupCollapsed(2, [monitor(2, 'down')]), true);
  assert.equal(publicApp.isGroupCollapsed(3, [monitor(3, 'up')]), false);
  assert.equal(publicApp.isGroupCollapsed(4, [monitor(4, 'down')]), true);
  assert.equal(publicApp.isGroupCollapsed(7, [monitor(7, 'warning')]), false);
  assert.equal(loadUi().publicApp.isGroupCollapsed(2, [monitor(2, 'up')]), true);
});

test('全部开合同步按钮语义和 inert，不保存跨次偏好', () => {
  const {context, publicApp, nodes, storedCalls} = loadUi();
  const sections = [section('1'), section('2')];
  context.document.querySelectorAll = () => sections;
  for (const id of ['public-group-controls', 'public-group-summary', 'public-expand-all', 'public-collapse-all']) {
    nodes.set(id, {hidden: false, textContent: '', setAttribute() {}});
  }
  publicApp.toggleAllGroups(true);
  for (const item of sections) {
    assert.equal(item.attributes.get('aria-expanded'), 'false');
    assert.equal(item.body.inert, true);
    assert.equal(item.label.textContent, '展开');
  }
  publicApp.toggleAllGroups(false);
  for (const item of sections) {
    assert.equal(item.attributes.get('aria-expanded'), 'true');
    assert.equal(item.body.inert, false);
  }
  assert.deepEqual(storedCalls, []);
});

test('异常摘要按分组和名称排序，分类合计、截断名称并通过文本安全渲染', () => {
  const {ui, nodes} = loadUi();
  for (const id of ['health-banner', 'health-title', 'health-description', 'health-symbol']) {
    nodes.set(id, {textContent: '', innerHTML: '', setAttribute() {}});
  }
  const groups = [{id: 2}, {id: 1}];
  const members = [monitor(1, 'down', {name: 'Zeta'}), monitor(2, 'down', {name: 'Alpha', group_id: 2}),
    monitor(3, 'warning', {name: '<img src=x>'}), monitor(4, 'down', {name: 'Beta'}),
    monitor(5, 'down', {name: 'Gamma'}), monitor(6, 'down', {enabled: 0, name: '暂停服务'})];
  ui.updateHealth(members, {detailed: true, groups});
  assert.equal(nodes.get('health-title').textContent, '5 个服务异常');
  assert.equal(nodes.get('health-description').textContent, '离线 4 个：Alpha、Beta、Gamma等 4 个；波动 1 个：<img src=x>');
  assert.equal(nodes.get('health-description').innerHTML, '');
  const longName = '长'.repeat(21);
  assert.equal(ui.describeProblems([monitor(1, 'down', {name: longName})]), `离线 1 个：${'长'.repeat(19)}…`);
  for (const [data, title] of [
    [[monitor(1, 'up')], '所有服务运行正常'], [[monitor(1, 'unknown')], '1 个服务等待检测'],
    [[monitor(1, 'down', {enabled: 0})], '所有服务已暂停检测'], [[], '准备好，迎接第一次心跳']
  ] as const) {
    ui.updateHealth(data, {detailed: true, groups});
    assert.equal(nodes.get('health-title').textContent, title);
    assert.doesNotMatch(nodes.get('health-description').textContent, /Alpha|<img/);
  }
});

test('两页状态条失败保留数据，恢复后更新，迟到响应不能覆盖最新结果', async () => {
  for (const name of ['publicApp', 'app'] as const) {
    const loaded = loadUi();
    const target = loaded[name];
    target.monitors = [monitor(1, 'up', {statusBar24h: null})];
    target.updateMonitorStatusBarDom = () => {};
    await target.loadStatusBars();
    assert.equal(target.statusBarsState, 'error');
    const pending: ((value: unknown) => void)[] = [];
    loaded.context.fetch = () => new Promise(resolve => pending.push(resolve));
    const first = target.loadStatusBars();
    const second = target.loadStatusBars();
    pending[1]({ok: true, json: async () => [{monitorId: 1, statusBar24h: bars('up', end + 60000)}]});
    await second;
    pending[0]({ok: true, json: async () => [{monitorId: 1, statusBar24h: bars('down')}]});
    await first;
    assert.equal(target.statusBarsState, 'ready');
    assert.equal(target.monitors[0].statusBar24h[0].segments[0], 'up');
    const saved = target.monitors[0].statusBar24h;
    loaded.context.fetch = async () => ({ok: false});
    await target.loadStatusBars();
    assert.equal(target.statusBarsState, 'error');
    assert.equal(target.monitors[0].statusBar24h, saved);
  }
});

test('局部刷新只汇总当前分组 DOM 成员，并刷新同色状态条的时间提示', () => {
  const {ui} = loadUi();
  let latestHtml = '', updates = 0;
  const bar = {set outerHTML(html: string) {latestHtml = html; updates++;}};
  const group = {querySelector: () => bar, querySelectorAll: () => [{getAttribute: () => '1'}]};
  const container = {querySelectorAll: () => [group]};
  const members = [monitor(1, 'up'), monitor(2, 'down')];
  ui.groupHistory.update(container, members, 'ready');
  assert.match(latestHtml, /离线 0 个 · 波动 0 个 · 正常 1 个 · 无数据 0 个/);
  const previous = latestHtml;
  ui.groupHistory.update(container, members, 'ready');
  assert.equal(updates, 1);
  members[0].statusBar24h = bars('up', end + 60000);
  ui.groupHistory.update(container, members, 'ready');
  assert.notEqual(latestHtml, previous);
  assert.equal(updates, 2);
});

test('合成 HTTP 场景验证公开权限、分组成员和现有批量状态条接口', () => {
  const result = spawnSync(process.execPath, ['node_modules/tsx/dist/cli.mjs', 'tests/fixtures/ui-dev-server.ts', 'group-status'],
    {encoding: 'utf8', timeout: 30000, windowsHide: true});
  assert.equal(result.status, 0, result.error?.message || result.stderr || result.stdout);
  assert.match(result.stdout, /SCENARIO PASSED: group-status/);
});
