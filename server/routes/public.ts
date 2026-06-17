import type { Express, Request, Response } from 'express';
import type { Pool } from 'mysql2/promise';
import type { MonitorGroupRow, MonitorRow, UptimeAggRow } from '../core/db-types.js';
import { execQuery } from '../core/db-utils.js';
import { buildStatusBars24h } from '../features/status-bars.js';

interface RouteLogger {
  warn(message: string): void;
  error(message: string): void;
}

interface PublicRoutesContext {
  getPool(): Pool | null;
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
           WHERE checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
             AND monitor_id IN (${inPlaceholders})
           GROUP BY monitor_id`,
          ids
        );
        uptimeRows.forEach((r: UptimeAggRow) => {
          uptimeMap.set(r.monitor_id, {
            total: Number(r.total_checks) || 0,
            up: Number(r.up_checks) || 0,
          });
        });
      }

      const monitorsWithUptime = rows.map((monitor: MonitorRow) => {
        const u = uptimeMap.get(monitor.id) || {total: 0, up: 0};
        const uptime_24h = u.total > 0 ? (u.up / u.total) * 100 : null;
        return {...monitor, uptime_24h};
      });

      res.json(monitorsWithUptime);
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
        `SELECT monitor_id, status, checked_at, message
         FROM check_history
         WHERE checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
           AND monitor_id IN (${inPlaceholders})
         ORDER BY monitor_id, checked_at`,
        ids
      );

      res.json(buildStatusBars24h(ids, historyRows));
    } catch (e: unknown) {
      logger.error(`公开API错误 ${JSON.stringify({path: req.path, method: req.method, error: (e as Error).message})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });

  app.get('/api/public/stats', async (req: Request, res: Response) => {
    try {
      const [rows] = await execQuery(ctx.getPool()!,
        `SELECT COUNT(*)                          as total,
                SUM(IF(status = 'up', 1, 0))      as up,
                SUM(IF(status = 'down', 1, 0))    as down,
                SUM(IF(status = 'unknown', 1, 0)) as unknown
         FROM monitors
         WHERE is_public = 1
           AND enabled = 1`
      );

      const stats = rows[0] || {total: 0, up: 0, down: 0, unknown: 0};

      const [uptimeRows] = await execQuery(ctx.getPool()!,
        `SELECT m.id,
                COUNT(h.id)                                            as total_checks,
                SUM(IF(h.status = 'up' OR h.status = 'warning', 1, 0)) as up_checks
         FROM monitors m
                  LEFT JOIN check_history h ON m.id = h.monitor_id
             AND h.checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         WHERE m.is_public = 1
           AND m.enabled = 1
         GROUP BY m.id`
      );

      let totalUptime = 0;
      let monitorCount = 0;

      uptimeRows.forEach((row: UptimeAggRow) => {
        if (row.total_checks > 0) {
          const uptime = (row.up_checks / row.total_checks) * 100;
          totalUptime += uptime;
          monitorCount++;
        }
      });

      stats.uptime_24h = monitorCount > 0 ? (totalUptime / monitorCount) : 100;

      res.json(stats);
    } catch (e) {
      logger.error(`公开API错误 ${JSON.stringify({path: req.path, method: req.method, error: (e as Error).message})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });
}
