import type {DatabaseClient} from '../core/db-utils.js';
import {execQuery} from '../core/db-utils.js';

export interface ResponseStats {
  avgResponse: number | null;
  p99Response: number | null;
}

/** 用全部有效响应计算平均延迟和最近秩 P99；不把无响应或超时换算成延迟。 */
export function calculateResponseStats(
  records: readonly {response_time?: unknown; stats_excluded?: unknown}[]
): ResponseStats {
  const values = records.filter(record => !record.stats_excluded).map(record => record.response_time)
    .filter((value): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0)
    .sort((a, b) => a - b);
  return {
    avgResponse: values.length ? Math.round(values.reduce((sum, value) => sum + value, 0) / values.length) : null,
    p99Response: values.length ? values[Math.ceil(values.length * 0.99) - 1] : null
  };
}

/** 每次列表请求只查询一次历史，限定到当前可见监控及同一个 24 小时窗口。 */
export async function loadResponseStats24h(
  pool: DatabaseClient,
  monitorIds: number[],
  endMs = Date.now()
): Promise<Map<number, ResponseStats>> {
  const recordsByMonitor = new Map<number, {response_time?: unknown}[]>(monitorIds.map(id => [id, []]));
  if (!recordsByMonitor.size) return new Map();
  const ids = [...recordsByMonitor.keys()];
  const [rows] = await execQuery(pool,
    `SELECT monitor_id, response_time
     FROM check_history
     WHERE monitor_id IN (${ids.map(() => '?').join(',')})
       AND checked_at >= ? AND checked_at < ?
       AND stats_excluded = 0
       AND response_time IS NOT NULL AND response_time >= 0`,
    [...ids, new Date(endMs - 24 * 3600000), new Date(endMs)]
  );
  for (const row of rows) recordsByMonitor.get(Number(row.monitor_id))?.push(row);
  return new Map([...recordsByMonitor].map(([id, records]) => [id, calculateResponseStats(records)]));
}
