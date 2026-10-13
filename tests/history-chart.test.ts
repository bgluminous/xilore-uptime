import assert from 'node:assert/strict';
import {test} from 'node:test';
import {buildHistoryChart, HISTORY_RANGE_CONFIG} from '../server/features/history-chart.js';

const end = Date.parse('2026-10-11T08:00:00Z');
const hour = 3600000;
const record = (time: number, status: 'up' | 'down' | 'warning' = 'up', response: number | null = 100) => ({
  checked_at: new Date(time).toISOString(), status, response_time: response
});

test('每小时检测在 24 小时内连续呈现 24 个真实采样点', () => {
  const records = Array.from({length: 24}, (_, i) => record(end - (23.5 - i) * hour, 'up', 100 + i));
  const points = buildHistoryChart(records, HISTORY_RANGE_CONFIG['24h'], 3600, end);
  assert.equal(points.length, 24);
  assert(points.every(point => point.count === 1 && point.status === 'up'));
  assert.deepEqual(points.map(point => point.response_time), records.map(row => row.response_time));
  assert.equal(Date.parse(points.at(-1)!.checked_at), end);
});

test('六档范围兼容 45 分钟、1 小时和 2 小时检测，范围短于间隔仍保留单点', () => {
  for (const interval of [2700, 3600, 7200]) {
    for (const range of Object.values(HISTORY_RANGE_CONFIG)) {
      const start = end - range.hours * hour;
      const records = [];
      for (let at = end - 1000; at >= start; at -= interval * 1000) records.push(record(at));
      const points = buildHistoryChart(records, range, interval, end);
      assert(points.length >= 1 && points.length <= range.chartPoints);
      assert(points.every(point => point.count > 0));
      assert.equal(points.reduce((sum, point) => sum + point.count, 0), records.length);
      assert.equal(Date.parse(points.at(-1)!.checked_at), end);
    }
  }
});

test('真正漏检与离线保留独立状态，不补齐响应值或伪造检测次数', () => {
  const records = Array.from({length: 24}, (_, i) => record(end - (23.5 - i) * hour));
  records[8] = record(end - 15.5 * hour, 'down', null);
  records.splice(12, 1);
  const points = buildHistoryChart(records, HISTORY_RANGE_CONFIG['24h'], 3600, end);
  assert.equal(points[8].status, 'down');
  assert.equal(points[8].count, 1);
  assert.equal(points[8].response_time, null);
  assert.equal(points[12].status, null);
  assert.equal(points[12].count, 0);
  assert.equal(points[12].response_time, null);
});

test('聚合包含重试/手动检测时，仅用有响应的记录求均值并保留状态优先级与零毫秒', () => {
  const points = buildHistoryChart([
    record(end - 1000, 'up', 0), record(end - 2000, 'warning', 200),
    record(end - 3000, 'down', null)
  ], HISTORY_RANGE_CONFIG['24h'], 3600, end);
  assert.deepEqual(points.at(-1), {
    checked_at: new Date(end).toISOString(), response_time: 100, status: 'down', count: 3,
    min_response_time: 0, max_response_time: 200
  });
});

test('不能整除的间隔覆盖完整窗口，边界记录只计算一次，忽略窗口外及非法时间', () => {
  const start = end - hour;
  const points = buildHistoryChart([
    record(start - 1), record(start), record(start + 450000), record(end - 1), record(end),
    {checked_at: 'invalid', status: 'up', response_time: 1}
  ], HISTORY_RANGE_CONFIG['1h'], 420, end);
  assert.equal(points.length, 8);
  assert.equal(points[0].count, 1);
  assert.equal(points[1].count, 1);
  assert.equal(points.at(-1)!.count, 1);
  assert.equal(points.reduce((sum, point) => sum + point.count, 0), 3);
});

test('高频检测保留原有采样精度，空数据不产生虚假的在线或零毫秒', () => {
  for (const range of Object.values(HISTORY_RANGE_CONFIG)) {
    for (const interval of [10, 60, 0, NaN]) {
      const points = buildHistoryChart([], range, interval, end);
      assert.equal(points.length, range.chartPoints);
      assert(points.every(point => point.count === 0 && point.status === null && point.response_time === null));
    }
  }
});
