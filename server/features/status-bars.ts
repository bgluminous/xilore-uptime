import type { CheckHistoryRow } from '../core/db-types.js';
import type {MaintenanceInterval} from './maintenance.js';

export function buildStatusBars24h(monitorIds: number[], historyRows: CheckHistoryRow[], maintenance: MaintenanceInterval[] = [], endMs = Date.now()): { monitorId: number; statusBar24h: any[] }[] {
  const oneHourMs = 60 * 60 * 1000;
  const segmentMs = 5 * 60 * 1000;
  const start24hMs = endMs - 24 * oneHourMs;

  const bucketsByMonitor = new Map();
  for (const id of monitorIds) {
    bucketsByMonitor.set(id, Array.from({length: 24}, () => []));
  }

  for (const row of historyRows) {
    const monitorId = Number(row.monitor_id);
    const buckets = bucketsByMonitor.get(monitorId);
    if (!buckets) continue;

    const checkedAt = row.checked_at instanceof Date ? row.checked_at : new Date(row.checked_at);
    const t = checkedAt.getTime();
    if (Number.isNaN(t) || t < start24hMs || t >= endMs) continue;

    const hourIdx = Math.floor((t - start24hMs) / oneHourMs);
    if (hourIdx < 0 || hourIdx >= 24) continue;
    buckets[hourIdx].push(row);
  }

  const priority = {down: 4, warning: 3, maintenance: 2, up: 1};

  return monitorIds.map((id) => {
    const buckets = bucketsByMonitor.get(id) || Array.from({length: 24}, () => []);
    const statusBar24h = buckets.map((records: CheckHistoryRow[], hourIdx: number) => {
      const hourStartMs = start24hMs + hourIdx * oneHourMs;
      const hourEndMs = hourStartMs + oneHourMs;

      const segments = new Array(12).fill(null);
      let upChecks = 0;
      let downChecks = 0;
      let warningChecks = 0;
      let lastUp = null;
      let lastWarning = null;
      let lastDown = null;

      for (const r of records) {
        const checkedAt = r.checked_at instanceof Date ? r.checked_at : new Date(r.checked_at);
        const t = checkedAt.getTime();
        if (Number.isNaN(t) || t < hourStartMs || t >= hourEndMs) continue;

        const segIdx = Math.min(11, Math.max(0, Math.floor((t - hourStartMs) / segmentMs)));
        const current = segments[segIdx];
        const display = r.in_maintenance ? 'maintenance' : r.status;
        if (!current || priority[display] > priority[current]) {
          segments[segIdx] = display;
        }

        if (r.stats_excluded) continue;
        if (r.status === 'up') {
          upChecks++;
          lastUp = r;
        } else if (r.status === 'down') {
          downChecks++;
          lastDown = r;
        } else if (r.status === 'warning') {
          warningChecks++;
          lastWarning = r;
        }
      }

      for (let i = 0; i < 12; i++) {
        if (maintenance.some(window => window.monitor_id === id && window.start < hourStartMs + (i + 1) * segmentMs &&
            window.end > hourStartMs + i * segmentMs) && !['down', 'warning'].includes(segments[i])) segments[i] = 'maintenance';
      }

      let lastKnown = null;
      for (let i = 0; i < segments.length; i++) {
        if (segments[i]) {
          lastKnown = segments[i] === 'maintenance' ? null : segments[i];
        } else if (lastKnown) {
          segments[i] = lastKnown;
        }
      }

      const firstKnownIndex = segments.findIndex((s) => s !== null);
      if (firstKnownIndex > 0 && segments[firstKnownIndex] !== 'maintenance') {
        for (let i = 0; i < firstKnownIndex; i++) {
          segments[i] = segments[firstKnownIndex];
        }
      }

      const totalChecks = records.filter(record => !record.stats_excluded).length;
      const uptime = totalChecks > 0 ? ((upChecks + warningChecks) / totalChecks) * 100 : null;
      const status = downChecks > 0 ? 'down' : warningChecks > 0 ? 'warning' : upChecks > 0 ? 'up' : null;
      const chosen = lastDown || lastWarning || lastUp;
      const chosenTime = chosen?.checked_at
        ? (chosen.checked_at instanceof Date ? chosen.checked_at : new Date(chosen.checked_at))
        : null;

      return {
        status,
        startTime: new Date(hourStartMs).toISOString(),
        endTime: new Date(hourEndMs).toISOString(),
        checkTime: chosenTime ? chosenTime.toISOString() : null,
        message: chosen?.message || null,
        totalChecks,
        maintenanceChecks: records.filter(record => record.in_maintenance).length,
        excludedChecks: records.length - totalChecks,
        downChecks,
        warningChecks,
        uptime,
        segments,
      };
    });

    return {monitorId: id, statusBar24h};
  });
}
