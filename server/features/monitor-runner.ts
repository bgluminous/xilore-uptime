import type {DatabaseClient} from '../core/db-utils.js';
import type {MonitorRow} from '../core/db-types.js';
import {assertWritable} from '../core/runtime-mode.js';
import {singleCheck} from './monitor-checks.js';
import {enqueueMaintenanceRecheck} from './content-notifications.js';
import {dispatchMonitorNotification} from './notifications.js';
import {maintenanceRecoveryNotification, syncMonitorMaintenance} from './maintenance.js';

type CheckResult = Awaited<ReturnType<typeof singleCheck>> & {skipped?: boolean};

export function createMonitorRunner(ctx: {
  getPool(): DatabaseClient;
  logger: Parameters<typeof singleCheck>[1] & Parameters<typeof dispatchMonitorNotification>[0]['logger'];
  check?: typeof singleCheck;
  notify?: typeof dispatchMonitorNotification;
  now?: () => number;
}) {
  const inFlight = new Map<number, Promise<CheckResult>>();
  async function run(monitor: MonitorRow): Promise<CheckResult> {
    assertWritable();
    const db = ctx.getPool();
    const now = () => ctx.now?.() ?? Date.now();
    const initial = await db.transaction(tx => syncMonitorMaintenance(tx, monitor.id, now()));
    if (!initial) return {status: 'unknown', responseTime: null, message: '监控已删除', skipped: true};
    if (!initial.policy.continueChecks) {
      return {status: 'maintenance', responseTime: null, message: '维护期间已停止检测', skipped: true};
    }
    let result: Awaited<ReturnType<typeof singleCheck>>;
    let retries = 0;
    const maxRetries = Math.min(initial.monitor.retries || 0, 3);
    do {
      result = await (ctx.check || singleCheck)(initial.monitor, ctx.logger);
      if (result.status !== 'down' || retries >= maxRetries) break;
      await new Promise(resolve => setTimeout(resolve, 1000));
      retries++;
    } while (true);
    const historyStatus = retries > 0 && result.status === 'up' ? 'warning' : result.status;
    if (retries) result.message += ` (重试 ${retries} 次${result.status === 'up' ? '后成功' : ''})`;
    const checkedAt = now();
    const notification = await db.transaction(async tx => {
      const state = await syncMonitorMaintenance(tx, monitor.id, checkedAt);
      if (!state) return null;
      const responseTime = result.responseTime ?? null;
      const ssl = typeof result.ssl_days_remaining === 'number';
      await tx.execute(`UPDATE monitors SET status = ?, last_check = ?, last_response_time = ?
        ${ssl ? ', ssl_days_remaining = ?' : ''} WHERE id = ?`,
      [result.status, new Date(checkedAt), responseTime, ...(ssl ? [result.ssl_days_remaining] : []), monitor.id]);
      const [written] = await tx.execute(`INSERT INTO check_history
        (monitor_id, status, response_time, message, checked_at, in_maintenance, stats_excluded)
        VALUES (?, ?, ?, ?, ?, ?, ?)`, [monitor.id, historyStatus, responseTime, result.message,
        new Date(checkedAt), Number(state.policy.active), Number(state.policy.excludeStats)]);
      if (state.policy.suppressAlerts) return null;
      if (state.pending) {
        await tx.execute('UPDATE maintenance_runtime SET recheck_pending = 0, baseline_status = NULL WHERE monitor_id = ?', [monitor.id]);
        if (!maintenanceRecoveryNotification(state.baseline, historyStatus)) return null;
      }
      const event = {type: 'status' as const, monitor: state.monitor,
        oldStatus: state.pending ? state.baseline : state.monitor.status,
        newStatus: historyStatus, message: result.message, responseTime, timestamp: new Date(checkedAt), force: state.pending};
      if (state.pending) {await enqueueMaintenanceRecheck(tx, event, written.insertId, checkedAt); return null;}
      return event;
    });
    if (notification) (ctx.notify || dispatchMonitorNotification)({pool: db, logger: ctx.logger}, notification);
    await db.execute('DELETE FROM check_history WHERE monitor_id = ? AND checked_at < DATE_SUB(NOW(), INTERVAL 7 DAY)', [monitor.id]);
    return result;
  }
  return (monitor: MonitorRow): Promise<CheckResult> => {
    assertWritable();
    if (inFlight.has(monitor.id)) return inFlight.get(monitor.id)!;
    const promise = run(monitor).finally(() => inFlight.delete(monitor.id));
    inFlight.set(monitor.id, promise);
    return promise;
  };
}
