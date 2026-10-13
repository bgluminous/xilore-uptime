import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {test} from 'node:test';
import type {DatabaseClient} from '../server/core/db-utils.js';
import {calculateResponseStats, loadResponseStats24h} from '../server/features/response-stats.js';

const records = (values: unknown[]) => values.map(response_time => ({response_time}));

test('完整原始样本计算平均值和最近秩 P99，排序不修改输入', () => {
  const input = records(Array.from({length: 100}, (_, i) => 100 - i));
  const original = structuredClone(input);
  assert.deepEqual(calculateResponseStats(input), {avgResponse: 51, p99Response: 99});
  assert.deepEqual(input, original);
});

test('零毫秒、重复值、小样本和非整齐秩，不插值或伪造样本', () => {
  for (const values of [[0], [0, 0, 0], [42], [42, 42]]) {
    assert.deepEqual(calculateResponseStats(records(values)), {avgResponse: values[0], p99Response: values[0]});
  }
  assert.deepEqual(calculateResponseStats(records([5, 1, 3])), {avgResponse: 3, p99Response: 5});
  assert.deepEqual(calculateResponseStats(records(Array.from({length: 101}, (_, i) => i + 1))),
    {avgResponse: 51, p99Response: 100});
});

test('平均值按原始样本权重计算并四舍五入到毫秒', () => {
  assert.deepEqual(calculateResponseStats(records([0, 1])), {avgResponse: 1, p99Response: 1});
  assert.deepEqual(calculateResponseStats(records([...Array(100).fill(1), 1000])),
    {avgResponse: 11, p99Response: 1});
});

test('空记录、超时、非法值不进入统计；有效零值和非在线状态仍可参与', () => {
  for (const values of [[], [null, null], [undefined, NaN, Infinity, -Infinity, -1, '123', '', false]]) {
    assert.deepEqual(calculateResponseStats(records(values)), {avgResponse: null, p99Response: null});
  }
  const input = [{response_time: 0, status: 'warning'}, {response_time: 30, status: 'down'},
    {response_time: null, status: 'down'}, {response_time: NaN, status: 'up'}];
  assert.deepEqual(calculateResponseStats(input), {avgResponse: 15, p99Response: 30});
});

test('24 小时批量查询包含起点、排除终点；按监控隔离，一次查询且空列表不查询', async () => {
  const end = Date.parse('2026-10-11T08:00:00Z');
  const start = end - 86400000;
  let calls = 0;
  const history = [
    {monitor_id: 1, checked_at: start - 1, response_time: 9999},
    {monitor_id: 1, checked_at: start, response_time: 10},
    {monitor_id: 1, checked_at: end - 1, response_time: 20},
    {monitor_id: 1, checked_at: end, response_time: 9999},
    {monitor_id: 2, checked_at: start, response_time: 0},
    {monitor_id: 3, checked_at: start, response_time: 90000}
  ];
  const pool: DatabaseClient = {
    async execute(sql, values) {
      calls++;
      assert.match(sql, /monitor_id IN \(\?,\?,\?\)/);
      assert.match(sql, /checked_at >= \? AND checked_at < \?/);
      assert.deepEqual(values, [1, 2, 4, new Date(start), new Date(end)]);
      const ids = values!.slice(0, -2);
      return [history.filter(row => ids.includes(row.monitor_id) && row.checked_at >= start && row.checked_at < end), []];
    },
    async end() {}
  };
  assert.deepEqual(await loadResponseStats24h(pool, [], end), new Map());
  assert.equal(calls, 0);
  assert.deepEqual(await loadResponseStats24h(pool, [1, 2, 4, 1], end), new Map([
    [1, {avgResponse: 15, p99Response: 20}],
    [2, {avgResponse: 0, p99Response: 0}],
    [4, {avgResponse: null, p99Response: null}]
  ]));
  assert.equal(calls, 1);
});

test('真实 HTTP 接口覆盖权限、三个展示位置的数据、六档范围与全量样本', () => {
  const result = spawnSync(process.execPath, ['node_modules/tsx/dist/cli.mjs', 'tests/fixtures/ui-dev-server.ts', 'response-stats'],
    {encoding: 'utf8', timeout: 30000, windowsHide: true});
  assert.equal(result.status, 0, result.error?.message || result.stderr || result.stdout);
  assert.match(result.stdout, /SCENARIO PASSED: response-stats/);
});
