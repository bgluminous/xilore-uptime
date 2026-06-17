import type { Express, RequestHandler, Request, Response } from 'express';
import type { Pool } from 'mysql2/promise';
import type { MonitorGroupRow } from '../core/db-types.js';
import { execQuery } from '../core/db-utils.js';

interface RouteLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

interface GroupRoutesContext {
  getPool(): Pool;
  logger: RouteLogger;
  authMiddleware: RequestHandler;
}

export function registerGroupRoutes(app: Express, ctx: GroupRoutesContext): void {
  const {authMiddleware, logger} = ctx;

  app.get('/api/groups', authMiddleware, async (req: Request, res: Response) => {
    try {
      const [rows] = await execQuery(ctx.getPool(), 'SELECT id, name, sort_order FROM monitor_groups ORDER BY sort_order, id');
      res.json(rows.map((r: MonitorGroupRow) => ({
        id: r.id,
        name: r.name,
        sort_order: r.sort_order ?? 0
      })));
    } catch (e: unknown) {
      logger.error(`API 错误 ${JSON.stringify({path: req.path, method: req.method, error: (e as Error).message, user: req.user?.username})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });

  app.post('/api/groups', authMiddleware, async (req: Request, res: Response) => {
    const {name, description} = req.body;

    if (!name) {
      logger.warn(`创建分组失败 - 名称为空 ${JSON.stringify({user: req.user?.username})}`);
      return res.status(400).json({error: '分组名称不能为空'});
    }

    try {
      const [existing] = await execQuery(ctx.getPool(),
        'SELECT id FROM monitor_groups WHERE name = ?',
        [name]
      );

      if (existing.length > 0) {
        logger.warn(`创建分组失败 - 名称重复 ${JSON.stringify({name, user: req.user?.username})}`);
        return res.status(400).json({error: '分组名称已存在'});
      }

      const [maxRows] = await execQuery(ctx.getPool(), 'SELECT COALESCE(MAX(sort_order), 0) AS max_order FROM monitor_groups');
      const nextOrder = (maxRows[0]?.max_order || 0) + 1;
      const [result] = await execQuery(ctx.getPool(),
        'INSERT INTO monitor_groups (name, description, sort_order) VALUES (?, ?, ?)',
        [name, description || null, nextOrder]
      );
      logger.info(`创建分组成功 ${JSON.stringify({groupId: result.insertId, name, user: req.user?.username})}`);
      res.json({id: result.insertId, name, sort_order: nextOrder});
    } catch (e) {
      logger.error(`创建分组失败 ${JSON.stringify({name, error: e.message, user: req.user?.username})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });

  app.put('/api/groups/:id', authMiddleware, async (req: Request, res: Response) => {
    const {name, description, sort_order} = req.body;
    const id = req.params.id;

    try {
      if (name !== undefined && name !== null) {
        const [existing] = await execQuery(ctx.getPool(),
          'SELECT id FROM monitor_groups WHERE name = ? AND id != ?',
          [name, id]
        );

        if (existing.length > 0) {
          logger.warn(`更新分组失败 - 名称重复 ${JSON.stringify({groupId: id, name, user: req.user?.username})}`);
          return res.status(400).json({error: '分组名称已存在'});
        }
      }

      const updates = [];
      const values = [];

      if (name !== undefined && name !== null) {
        updates.push('name = ?');
        values.push(name);
      }

      if (description !== undefined) {
        updates.push('description = ?');
        values.push(description);
      }

      if (sort_order !== undefined && sort_order !== null) {
        updates.push('sort_order = ?');
        values.push(sort_order);
      }

      if (updates.length === 0) {
        const [group] = await execQuery(ctx.getPool(), 'SELECT id, name, sort_order FROM monitor_groups WHERE id = ?', [id]);
        return res.json(group[0] ? {
          id: group[0].id,
          name: group[0].name,
          sort_order: group[0].sort_order ?? 0
        } : null);
      }

      values.push(id);
      await execQuery(ctx.getPool(),
        `UPDATE monitor_groups
         SET ${updates.join(', ')}
         WHERE id = ?`,
        values
      );

      const [updated] = await execQuery(ctx.getPool(), 'SELECT id, name, sort_order FROM monitor_groups WHERE id = ?', [id]);

      logger.info(`更新分组成功 ${JSON.stringify({groupId: id, name, sort_order, user: req.user?.username})}`);
      res.json(updated[0] ? {
        id: updated[0].id,
        name: updated[0].name,
        sort_order: updated[0].sort_order ?? 0
      } : null);
    } catch (e) {
      logger.error(`更新分组失败 ${JSON.stringify({groupId: id, error: e.message, user: req.user?.username})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });

  app.delete('/api/groups/:id', authMiddleware, async (req: Request, res: Response) => {
    const id = req.params.id;

    try {
      const [updateResult] = await execQuery(ctx.getPool(), 'UPDATE monitors SET group_id = NULL WHERE group_id = ?', [id]);
      await execQuery(ctx.getPool(), 'DELETE FROM monitor_groups WHERE id = ?', [id]);
      logger.info(`删除分组成功 ${JSON.stringify({
        groupId: id,
        affectedMonitors: updateResult.affectedRows,
        user: req.user?.username
      })}`);
      res.json({success: true});
    } catch (e) {
      logger.error(`删除分组失败 ${JSON.stringify({groupId: id, error: e.message, user: req.user?.username})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });
}
