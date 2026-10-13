import type { Express, Request, Response } from 'express';
import type { DatabaseClient } from '../core/db-utils.js';
import type { MonitorGroupRow, MonitorRow, UptimeAggRow } from '../core/db-types.js';
import { execQuery } from '../core/db-utils.js';
import { buildStatusBars24h } from '../features/status-bars.js';
import { loadResponseStats24h } from '../features/response-stats.js';
import {decorateMaintenance, loadMaintenanceIntervals, loadOverviewStats} from '../features/maintenance.js';

interface RouteLogger {
  warn(message: string): void;
  error(message: string): void;
}

interface PublicRoutesContext {
  getPool(): DatabaseClient | null;
  logger: RouteLogger;
}

export function registerPublicRoutes(app: Express, ctx: PublicRoutesContext): void {
  const {logger} = ctx;

  app.get('/api/public/title', async (req: Request, res: Response) => {
    try {
      const pool = ctx.getPool();
      if (!pool) {
        return res.json({title: '服务状态监控'});
      }

      try {
        const [rows] = await execQuery(pool,
          'SELECT value FROM settings WHERE key_name = ?',
          ['publicPageTitle']
        );

        const title = rows.length > 0 && rows[0].value
          ? rows[0].value
          : '服务状态监控';

        res.json({title});
      } catch (dbError) {
        logger.warn(`获取公开页面标题失败，使用默认值 ${JSON.stringify({error: dbError.message})}`);
        res.json({title: '服务状态监控'});
      }
    } catch (e: unknown) {
      logger.error(`公开API错误 ${JSON.stringify({path: req.path, method: req.method, error: (e as Error).message})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });

  app.get('/api/public/groups', async (req: Request, res: Response) => {
    try {
      const [rows] = await execQuery(ctx.getPool()!,
        `SELECT DISTINCT g.id, g.name, g.sort_order
         FROM monitor_groups g
                  INNER JOIN monitors m ON m.group_id = g.id
         WHERE m.is_public = 1
         ORDER BY g.sort_order, g.id`
      );
      res.json(rows.map((r: MonitorGroupRow) => ({
        id: r.id,
        name: r.name,
        sort_order: r.sort_order ?? 0
      })));
    } catch (e: unknown) {
      logger.error(`公开API错误 ${JSON.stringify({path: req.path, method: req.method, error: (e as Error).message})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });

  app.get('/api/public/monitors', async (req: Request, res: Response) => {
    const endMs = Date.now();
    try {
      const [rows] = await execQuery(ctx.getPool()!,
        'SELECT id, name, status, group_id, enabled, last_response_time, last_check FROM monitors WHERE is_public = 1 ORDER BY group_id, created_at DESC'
      );

      const ids = rows.map((m: MonitorRow) => m.id);
      const uptimeMap = new Map();
      if (ids.length > 0) {
        const inPlaceholders = ids.map(() => '?').join(',');
        const [uptimeRows] = await execQuery(ctx.getPool()!,
          `SELECT monitor_id,
                  COUNT(*)                                           as total_checks,
                  SUM(IF(status = 'up' OR status = 'warning', 1, 0)) as up_checks
           FROM check_history
           WHERE checked_at >= ? AND checked_at < ? AND stats_excluded = 0
             AND monitor_id IN (${inPlaceholders})
           GROUP BY monitor_id`,
          [new Date(endMs - 24 * 3600000), new Date(endMs), ...ids]
        );
        uptimeRows.forEach((r: UptimeAggRow) => {
          uptimeMap.set(r.monitor_id, {
            total: Number(r.total_checks) || 0,
            up: Number(r.up_checks) || 0,
          });
        });
      }

      const responseStats = await loadResponseStats24h(ctx.getPool()!, ids, endMs);
      const monitorsWithUptime = rows.map((monitor: MonitorRow) => {
        const u = uptimeMap.get(monitor.id) || {total: 0, up: 0};
        const uptime_24h = u.total > 0 ? (u.up / u.total) * 100 : null;
        return {
          ...monitor, uptime_24h,
          avg_response_24h: responseStats.get(monitor.id)?.avgResponse ?? null,
          p99_response_24h: responseStats.get(monitor.id)?.p99Response ?? null
        };
      });

      res.json(await decorateMaintenance(ctx.getPool()!, monitorsWithUptime, true, endMs));
    } catch (e: unknown) {
      logger.error(`公开API错误 ${JSON.stringify({path: req.path, method: req.method, error: (e as Error).message})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });

  app.get('/api/public/monitors/statusbars', async (req: Request, res: Response) => {
    try {
      const [rows] = await execQuery(ctx.getPool()!, 'SELECT id FROM monitors WHERE is_public = 1');
      const ids = rows.map((r: MonitorRow) => Number(r.id)).filter((v: number) => Number.isFinite(v));
      if (ids.length === 0) {
        return res.json([]);
      }

      const inPlaceholders = ids.map(() => '?').join(',');
      const [historyRows] = await execQuery(ctx.getPool()!,
        `SELECT monitor_id, status, checked_at, message, in_maintenance, stats_excluded
         FROM check_history
         WHERE checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
           AND monitor_id IN (${inPlaceholders})
         ORDER BY monitor_id, checked_at`,
        ids
      );

      const endMs = Date.now();
      const maintenance = await loadMaintenanceIntervals(ctx.getPool()!, ids, endMs - 86400000, endMs);
      // 原始错误消息可能包含目标地址；公开状态条只展示状态和聚合指标。
      res.json(buildStatusBars24h(ids, historyRows.map(row => ({...row, message: null})), maintenance, endMs));
    } catch (e: unknown) {
      logger.error(`公开API错误 ${JSON.stringify({path: req.path, method: req.method, error: (e as Error).message})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });

  app.get('/api/public/stats', async (_req: Request, res: Response) => {
    try {
      const stats = await loadOverviewStats(ctx.getPool()!, true);
      res.json({...stats, uptime_24h: stats.avgUptime24h});
    } catch { res.status(500).json({error: '公开统计数据读取失败'}); }
  });
}
