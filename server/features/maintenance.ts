import type {DatabaseClient, DatabaseExecutor} from '../core/db-utils.js';
import type {MaintenanceMembership, MaintenanceRow, MaintenanceRuntimeRow, MonitorRow} from '../core/db-types.js';
import {assertWritable, isUiDevMode} from '../core/runtime-mode.js';
import {enqueueContentEvent, processContentDeliveries} from './content-notifications.js';

export interface MaintenancePolicy {
  active: boolean;
  continueChecks: boolean;
  suppressAlerts: boolean;
  excludeStats: boolean;
}

export interface MaintenanceInterval { monitor_id: number; start: number; end: number; }

export function maintenancePhase(row: Pick<MaintenanceRow, 'starts_ms' | 'ends_ms' | 'cancelled_ms'>, now: number): MaintenanceRow['phase'] {
  if (row.cancelled_ms != null) return 'cancelled';
  if (Number(row.starts_ms) > now) return 'scheduled';
  if (row.ends_ms != null && Number(row.ends_ms) <= now) return 'completed';
  return 'active';
}

export function calculateMaintenancePolicy(rows: MaintenanceRow[], now: number): MaintenancePolicy {
  const active = rows.filter(row => maintenancePhase(row, now) === 'active');
  return {active: active.length > 0, continueChecks: active.every(row => !!row.continue_checks),
    suppressAlerts: active.some(row => !!row.suppress_alerts), excludeStats: active.some(row => !!row.exclude_stats)};
}

export async function loadActiveMaintenances(db: DatabaseExecutor, ids: number[], now: number): Promise<MaintenanceMembership[]> {
  if (!ids.length) return [];
  const [rows] = await db.execute(`SELECT w.*, mm.monitor_id FROM maintenances w
    JOIN maintenance_monitors mm ON mm.maintenance_id = w.id
    WHERE mm.monitor_id IN (${ids.map(() => '?').join(',')}) AND w.cancelled_ms IS NULL
      AND w.starts_ms <= ? AND (w.ends_ms IS NULL OR w.ends_ms > ?)`, [...ids, now, now]);
  return rows;
}

export async function decorateMaintenance(db: DatabaseExecutor, monitors: MonitorRow[], publicView = false, now = Date.now()): Promise<MonitorRow[]> {
  const rows = await loadActiveMaintenances(db, monitors.map(monitor => monitor.id), now);
  return monitors.map(monitor => {
    const active = rows.filter(row => Number(row.monitor_id) === Number(monitor.id));
    const policy = calculateMaintenancePolicy(active, now);
    return {...monitor,
      effective_status: !monitor.enabled ? 'paused' : policy.active ? 'maintenance' : monitor.status,
      maintenance: {active: policy.active,
        ...(!publicView ? {continue_checks: policy.continueChecks, suppress_alerts: policy.suppressAlerts,
          exclude_stats: policy.excludeStats} : {}),
        items: active.filter(row => !publicView || row.is_public).map(row => ({id: row.id, title: row.title,
          ends_at: row.ends_ms == null ? null : new Date(Number(row.ends_ms)).toISOString()}))}
    };
  });
}

export async function loadMaintenanceIntervals(db: DatabaseExecutor, ids: number[], start: number, end: number): Promise<MaintenanceInterval[]> {
  if (!ids.length) return [];
  const [rows] = await db.execute(`SELECT mm.monitor_id, w.starts_ms, w.ends_ms FROM maintenances w
    JOIN maintenance_monitors mm ON mm.maintenance_id = w.id
    WHERE mm.monitor_id IN (${ids.map(() => '?').join(',')}) AND w.cancelled_ms IS NULL
      AND w.starts_ms < ? AND (w.ends_ms IS NULL OR w.ends_ms > ?)`, [...ids, end, start]);
  return rows.map(row => ({monitor_id: Number(row.monitor_id), start: Math.max(start, Number(row.starts_ms)),
    end: Math.min(end, row.ends_ms == null ? end : Number(row.ends_ms))}));
}

export async function loadOverviewStats(db: DatabaseExecutor, publicView = false, now = Date.now()) {
  const [rows] = await db.execute(`SELECT id, status, enabled FROM monitors ${publicView ? 'WHERE is_public = 1' : ''}`);
  const monitors = await decorateMaintenance(db, rows, publicView, now);
  const active = monitors.filter(monitor => monitor.enabled);
  const ids = active.map(monitor => monitor.id);
  const [uptimes] = ids.length ? await db.execute(`SELECT monitor_id, COUNT(*) AS total_checks,
    SUM(IF(status IN ('up', 'warning'), 1, 0)) AS up_checks FROM check_history
    WHERE stats_excluded = 0 AND checked_at >= ? AND checked_at < ?
      AND monitor_id IN (${ids.map(() => '?').join(',')}) GROUP BY monitor_id`, [new Date(now - 86400000), new Date(now), ...ids]) : [[]];
  const rates = uptimes.filter(row => Number(row.total_checks) > 0).map(row => Number(row.up_checks) / Number(row.total_checks) * 100);
  return {total: publicView ? active.length : monitors.length, paused: monitors.length - active.length,
    up: active.filter(monitor => ['up', 'warning'].includes(String(monitor.effective_status))).length,
    down: active.filter(monitor => monitor.effective_status === 'down').length,
    unknown: active.filter(monitor => monitor.effective_status === 'unknown').length,
    maintenance: active.filter(monitor => monitor.effective_status === 'maintenance').length,
    avgUptime24h: rates.length ? rates.reduce((sum, value) => sum + value, 0) / rates.length : null};
}

/** 同一事务中锁定监控与静默基线；检测开始、完成和协调器都走这一入口。 */
export async function syncMonitorMaintenance(db: DatabaseExecutor, id: number, now: number) {
  const [monitors] = await db.execute('SELECT * FROM monitors WHERE id = ? FOR UPDATE', [id]);
  if (!monitors.length) return null;
  const monitor: MonitorRow = monitors[0];
  const policy = calculateMaintenancePolicy(await loadActiveMaintenances(db, [id], now), now);
  await db.execute(`INSERT INTO maintenance_runtime (monitor_id) VALUES (?)
    ON DUPLICATE KEY UPDATE monitor_id = VALUES(monitor_id)`, [id]);
  const [states] = await db.execute('SELECT * FROM maintenance_runtime WHERE monitor_id = ? FOR UPDATE', [id]);
  const state: MaintenanceRuntimeRow = states[0];
  const leavingSilence = !!state.silenced && !policy.suppressAlerts;
  const resumingChecks = !!state.checks_paused && policy.continueChecks;
  // 捕获进程停机、轮询间隙内已经完整经过的时段，水位防止重复安排首检。
  const observed = state.observed_ms == null
    ? (monitor.last_check ? new Date(monitor.last_check).getTime() : now) : Number(state.observed_ms);
  const [elapsed] = await db.execute(`SELECT w.suppress_alerts, w.continue_checks FROM maintenances w
    JOIN maintenance_monitors mm ON mm.maintenance_id = w.id
    WHERE mm.monitor_id = ? AND w.cancelled_ms IS NULL AND w.starts_ms <= ?
      AND w.ends_ms > ? AND w.ends_ms <= ?`, [id, now, observed, now]);
  const missed = elapsed.some(row => row.suppress_alerts || !row.continue_checks);
  const pending = !!state.recheck_pending || leavingSilence || resumingChecks || missed;
  let baseline = state.baseline_status;
  if (!state.recheck_pending && !state.silenced &&
      (policy.suppressAlerts || !policy.continueChecks || missed)) {
    const [latest] = await db.execute('SELECT status FROM check_history WHERE monitor_id = ? ORDER BY checked_at DESC, id DESC LIMIT 1', [id]);
    baseline = latest[0]?.status || monitor.status || 'unknown';
  }
  await db.execute(`UPDATE maintenance_runtime SET silenced = ?, checks_paused = ?,
    baseline_status = ?, recheck_pending = ?, observed_ms = ? WHERE monitor_id = ?`,
  [Number(policy.suppressAlerts), Number(!policy.continueChecks), baseline, Number(pending), Math.max(Number(state.observed_ms) || 0, now), id]);
  return {monitor, policy, baseline, pending};
}

export function maintenanceRecoveryNotification(baseline: string | null, status: string): boolean {
  return status === 'down' || status === 'warning' || (status === 'up' && ['down', 'warning'].includes(baseline));
}

export async function reconcileMaintenancePhases(db: DatabaseClient, now: number): Promise<void> {
  assertWritable();
  const [rows] = await db.execute("SELECT id FROM maintenances WHERE phase IN ('scheduled', 'active') ORDER BY id");
  for (const item of rows) {
    await db.transaction(async tx => {
      const [locked] = await tx.execute('SELECT * FROM maintenances WHERE id = ? FOR UPDATE', [item.id]);
      const row: MaintenanceRow = locked[0];
      if (!row) return;
      const phase = maintenancePhase(row, now);
      if (row.phase === phase) return;
      await tx.execute('UPDATE maintenances SET phase = ? WHERE id = ?', [phase, row.id]);
      if (phase === 'active' || phase === 'completed') {
        await enqueueContentEvent(tx, 'maintenance', row,
          phase === 'active' ? 'maintenance_started' : 'maintenance_completed', now);
      }
    });
  }
}

/** 所有定时器由调用者显式启动和关闭；读取接口从不推进数据库状态。 */
export function createMaintenanceCoordinator(ctx: {
  getPool(): DatabaseClient | null;
  check(monitor: MonitorRow): Promise<unknown>;
  logger: {error(message: string): void};
  now?: () => number;
}) {
  let timer: ReturnType<typeof setInterval> | undefined;
  let running: Promise<void> | undefined;
  let stopped = true;
  let delivering: Promise<void> | undefined;
  const checks = new Map<number, Promise<unknown>>();
  const tick = (): Promise<void> => {
    if (stopped || isUiDevMode()) return Promise.resolve();
    if (running) return running;
    running = (async () => {
      const db = ctx.getPool();
      if (!db) return;
      const now = ctx.now?.() ?? Date.now();
      await reconcileMaintenancePhases(db, now);
      const [monitors] = await db.execute('SELECT id FROM monitors ORDER BY id');
      for (const monitor of monitors) {
        if (stopped) break;
        const result = await db.transaction(tx => syncMonitorMaintenance(tx, monitor.id, now));
        if (result?.pending && result.monitor.enabled && result.policy.continueChecks && !result.policy.suppressAlerts) {
          // 检测自身会重新判断当前时间，等待中的首检不会穿透新的维护。
          if (!checks.has(monitor.id)) {
            const check = ctx.check(result.monitor).catch(() => ctx.logger.error('维护首检失败，将重试'))
              .finally(() => checks.delete(monitor.id));
            checks.set(monitor.id, check);
          }
        }
      }
      if (!stopped && !delivering) {
        delivering = processContentDeliveries(db, ctx.now?.() ?? Date.now())
          .catch(() => ctx.logger.error('通知队列处理失败，将重试')).finally(() => {delivering = undefined;});
      }
    })().catch(() => ctx.logger.error('维护协调失败，将在下一周期重试')).finally(() => {running = undefined;});
    return running;
  };
  return {
    start() {
      if (isUiDevMode() || !stopped) return;
      stopped = false;
      void tick();
      timer = setInterval(() => {void tick();}, 5000);
    },
    async stop() { stopped = true; clearInterval(timer); timer = undefined; await running; await delivering; await Promise.all(checks.values()); },
    tick
  };
}
