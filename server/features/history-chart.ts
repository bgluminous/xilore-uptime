import type {CheckHistoryRow} from '../core/db-types.js';
import type {MaintenanceInterval} from './maintenance.js';

interface HistoryRange {
  hours: number;
  chartPoints: number;
}

// 高频检测保留原有精度；低频检测按实际间隔降低采样密度。
export const HISTORY_RANGE_CONFIG: Record<string, HistoryRange> = {
  '1h': {hours: 1, chartPoints: 60},
  '6h': {hours: 6, chartPoints: 72},
  '12h': {hours: 12, chartPoints: 48},
  '24h': {hours: 24, chartPoints: 48},
  '7d': {hours: 24 * 7, chartPoints: 56},
  '30d': {hours: 24 * 30, chartPoints: 60}
};

type HistoryRecord = Pick<CheckHistoryRow, 'checked_at' | 'status' | 'response_time' | 'in_maintenance' | 'stats_excluded'>;

interface ChartPoint {
  checked_at: string;
  response_time: number | null;
  status: HistoryRecord['status'] | null;
  count: number;
  min_response_time: number | null;
  max_response_time: number | null;
  in_maintenance?: boolean;
  excluded_count?: number;
}

export function buildHistoryChart(
  history: HistoryRecord[],
  range: HistoryRange,
  intervalSeconds: number,
  endMs = Date.now(),
  maintenance: MaintenanceInterval[] = []
): ChartPoint[] {
  const durationMs = range.hours * 3600000;
  const defaultIntervalMs = durationMs / range.chartPoints;
  const checkIntervalMs = Number.isFinite(intervalSeconds) && intervalSeconds > 0
    ? intervalSeconds * 1000 : defaultIntervalMs;
  const pointCount = Math.max(1, Math.floor(durationMs / Math.max(defaultIntervalMs, checkIntervalMs)));
  // 均分整个所选范围，避免不能整除的检测间隔遗漏最早一段数据。
  const intervalMs = durationMs / pointCount;
  const startMs = endMs - durationMs;
  const buckets = Array.from({length: pointCount}, (_, index) => ({
    point: {
      checked_at: new Date(startMs + (index + 1) * intervalMs).toISOString(),
      response_time: null,
      status: null,
      count: 0,
      min_response_time: null,
      max_response_time: null
    } as ChartPoint,
    responseSum: 0,
    responseCount: 0
  }));
  const priority = {down: 3, warning: 2, up: 1};

  for (const record of history) {
    const checkedAt = new Date(record.checked_at).getTime();
    if (!Number.isFinite(checkedAt) || checkedAt < startMs || checkedAt >= endMs) continue;
    const bucket = buckets[Math.min(pointCount - 1, Math.floor((checkedAt - startMs) / intervalMs))];
    const point = bucket.point;
    point.count++;
    if (record.in_maintenance) point.in_maintenance = true;
    if (record.stats_excluded) point.excluded_count = (point.excluded_count || 0) + 1;
    if ((priority[record.status] || 0) > (priority[point.status] || 0)) point.status = record.status;
    if (!record.stats_excluded && record.response_time != null) {
      bucket.responseSum += record.response_time;
      bucket.responseCount++;
      point.min_response_time = point.min_response_time == null
        ? record.response_time : Math.min(point.min_response_time, record.response_time);
      point.max_response_time = point.max_response_time == null
        ? record.response_time : Math.max(point.max_response_time, record.response_time);
    }
  }

  return buckets.map(({point, responseSum, responseCount}, index) => ({
    ...point,
    ...(maintenance.some(window => window.start < startMs + (index + 1) * intervalMs && window.end > startMs + index * intervalMs)
      ? {in_maintenance: true} : {}),
    response_time: responseCount ? Math.round(responseSum / responseCount) : null
  }));
}
