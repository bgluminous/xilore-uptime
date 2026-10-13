import type {Express, Request, Response, RequestHandler} from 'express';
import type {DatabaseClient, DatabaseExecutor} from '../core/db-utils.js';
import type {AnnouncementRow, MaintenanceRow} from '../core/db-types.js';
import {ContentError, contentBoolean, contentChannels, contentId, contentText, contentTime,
  parseChannels, renderContent} from '../features/content.js';
import {enqueueContentEvent} from '../features/content-notifications.js';
import {maintenancePhase, syncMonitorMaintenance} from '../features/maintenance.js';

interface CommunicationsContext {
  getPool(): DatabaseClient;
  authMiddleware: RequestHandler;
  logger: {error(message: string): void};
  now?: () => number;
}

const admin: RequestHandler = (req, res, next) => {
  if (req.user?.role !== 'admin') { res.status(403).json({error: '仅管理员可管理公告与维护'}); return; }
  next();
};

function pageNumber(req: Request): number {
  const page = Number(req.query.page || 1);
  if (!Number.isSafeInteger(page) || page < 1 || page > 100000) throw new ContentError('页码无效');
  return page;
}

function checkRevision(row: {revision: number}, body: any): void {
  if (Number(body.revision) !== Number(row.revision)) throw new ContentError('内容已更新，请刷新后重试', 409);
}

function commonContent(body: any, old?: {title: string; body: string; channels: string}) {
  return {title: contentText(body.title ?? old?.title, '标题', 200),
    body: contentText(body.body ?? old?.body ?? '', '正文', 20000, false),
    channels: JSON.stringify(contentChannels(body.channels ?? (old ? parseChannels(old.channels) : [])))};
}

async function validateMonitors(db: DatabaseExecutor, value: unknown): Promise<number[]> {
  if (!Array.isArray(value) || !value.length || value.length > 1000) throw new ContentError('请选择 1 至 1000 个监控项');
  const ids = [...new Set(value.map(contentId))].sort((a, b) => a - b);
  const [rows] = await db.execute(`SELECT id FROM monitors WHERE id IN (${ids.map(() => '?').join(',')}) FOR UPDATE`, ids);
  if (rows.length !== ids.length) throw new ContentError('部分监控项已不存在，请重新选择');
  return ids;
}

export function registerCommunicationRoutes(app: Express, ctx: CommunicationsContext): void {
  const now = () => ctx.now?.() ?? Date.now();
  const wrap = (handler: (req: Request, res: Response) => Promise<unknown>): RequestHandler => async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    try { await handler(req, res); }
    catch (error) {
      if (error instanceof ContentError) { res.status(error.status).json({error: error.message}); return; }
      if ((error as any).code === 'UI_DEV_READ_ONLY') {
        res.status(403).json({error: (error as Error).message, code: 'UI_DEV_READ_ONLY'}); return;
      }
      ctx.logger.error(`公告或维护操作失败 ${JSON.stringify({path: req.path, method: req.method})}`);
      res.status(500).json({error: '操作失败，请稍后重试'});
    }
  };
  const secure = [ctx.authMiddleware, admin];

  app.post('/api/content/preview', ...secure, wrap(async (req, res) => {
    res.json({html: renderContent(contentText(req.body.body, '正文', 20000, false))});
  }));

  async function deliveries(db: DatabaseExecutor, type: string, ids: number[]) {
    if (!ids.length) return [];
    const [rows] = await db.execute(`SELECT owner_id, event_key, channel, state, attempts, last_error
      FROM content_deliveries WHERE owner_type = ? AND owner_id IN (${ids.map(() => '?').join(',')}) ORDER BY id DESC`, [type, ...ids]);
    return rows;
  }

  function announcementDto(row: AnnouncementRow, publicView: boolean) {
    return {id: row.id, title: row.title, body_html: renderContent(row.body), state: row.state,
      pinned: !!row.pinned, published_at: row.published_ms == null ? null : new Date(Number(row.published_ms)).toISOString(),
      updated_at: new Date(Number(row.updated_ms)).toISOString(),
      ...(!publicView ? {body: row.body, channels: parseChannels(row.channels), revision: row.revision} : {})};
  }

  // 两类内容先合并排序再分页，避免分别取一页后拼接造成时间线漏项或顺序跳动。
  app.get('/api/public/updates', wrap(async (req, res) => {
    const page = pageNumber(req);
    const past = req.query.history === '1';
    const timestamp = now();
    const db = ctx.getPool();
    const historyFilter = past ? '(w.cancelled_ms IS NOT NULL OR (w.ends_ms IS NOT NULL AND w.ends_ms <= ?))'
      : '(w.cancelled_ms IS NULL AND (w.ends_ms IS NULL OR w.ends_ms > ?))';
    const maintenanceFilter = `${historyFilter} AND w.is_public = 1
      AND EXISTS (SELECT 1 FROM maintenance_monitors mm JOIN monitors m ON m.id = mm.monitor_id
        WHERE mm.maintenance_id = w.id AND m.is_public = 1)`;
    const parameters = [past ? 'archived' : 'published', timestamp];
    const [[rows], [counts]] = await Promise.all([db.execute(`SELECT * FROM (
      SELECT 'announcements' AS kind, id, title, body, state, pinned,
        published_ms AS starts_ms, NULL AS ends_ms, NULL AS cancelled_ms,
        ${past ? 'updated_ms' : 'published_ms'} AS timeline_ms, ${past ? '0' : 'pinned'} AS priority
      FROM announcements WHERE state = ?
      UNION ALL
      SELECT 'maintenances' AS kind, w.id, w.title, w.body, NULL AS state, 0 AS pinned,
        w.starts_ms, w.ends_ms, w.cancelled_ms,
        ${past ? 'COALESCE(w.cancelled_ms, w.ends_ms)' : 'w.starts_ms'} AS timeline_ms, 0 AS priority
      FROM maintenances w WHERE ${maintenanceFilter}
      ) timeline ORDER BY priority DESC, timeline_ms DESC, kind, id DESC LIMIT 21 OFFSET ${(page - 1) * 20}`,
    parameters), db.execute(`SELECT (SELECT COUNT(*) FROM announcements WHERE state = ?) +
      (SELECT COUNT(*) FROM maintenances w WHERE ${maintenanceFilter}) AS total`, parameters)]);
    const visible = rows.slice(0, 20);
    const ids = visible.filter(row => row.kind === 'maintenances').map(row => row.id);
    const [members] = ids.length ? await db.execute(`SELECT mm.maintenance_id, m.id, m.name
      FROM maintenance_monitors mm JOIN monitors m ON m.id = mm.monitor_id
      WHERE mm.maintenance_id IN (${ids.map(() => '?').join(',')}) AND m.is_public = 1 ORDER BY m.id`, ids) : [[]];
    res.json({items: visible.map(row => ({kind: row.kind, id: row.id, title: row.title,
      body_html: renderContent(row.body), timeline_at: new Date(Number(row.timeline_ms)).toISOString(),
      state: row.kind === 'announcements' ? row.state : maintenancePhase(row, timestamp),
      pinned: !!row.pinned,
      ...(row.kind === 'announcements' ? {published_at: new Date(Number(row.starts_ms)).toISOString()} : {
        starts_at: new Date(Number(row.starts_ms)).toISOString(),
        ends_at: row.ends_ms == null ? null : new Date(Number(row.ends_ms)).toISOString(),
        monitors: members.filter(member => member.maintenance_id === row.id).map(({id, name}) => ({id, name}))
      })})), page, total: Number(counts[0].total), has_more: rows.length > 20});
  }));

  for (const publicView of [false, true]) {
    app.get(publicView ? '/api/public/announcements' : '/api/announcements',
      ...(!publicView ? secure : []), wrap(async (req, res) => {
        const page = pageNumber(req);
        const filter = publicView ? (req.query.history === '1' ? 'archived' : 'published') : req.query.state;
        if (filter && !['draft', 'published', 'archived'].includes(String(filter))) throw new ContentError('公告状态无效');
        const db = ctx.getPool();
        const [rows]: [AnnouncementRow[], unknown] = await db.execute(`SELECT * FROM announcements
          ${filter ? 'WHERE state = ?' : ''} ORDER BY pinned DESC, published_ms DESC, id DESC LIMIT 21 OFFSET ${(page - 1) * 20}`,
        filter ? [filter] : []);
        const visible = rows.slice(0, 20);
        const notifications = publicView ? [] : await deliveries(db, 'announcement', visible.map(row => row.id));
        res.json({items: visible.map(row => ({...announcementDto(row, publicView),
          ...(!publicView ? {deliveries: notifications.filter(item => item.owner_id === row.id)} : {})})),
        page, has_more: rows.length > 20});
      }));
  }

  app.post('/api/announcements', ...secure, wrap(async (req, res) => {
    const content = commonContent(req.body);
    const timestamp = now();
    const published = contentBoolean(req.body.publish, false);
    const id = await ctx.getPool().transaction(async tx => {
      const [result] = await tx.execute(`INSERT INTO announcements
        (title, body, state, pinned, channels, published_ms, created_ms, updated_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [content.title, content.body, published ? 'published' : 'draft', contentBoolean(req.body.pinned, false),
        content.channels, published ? timestamp : null, timestamp, timestamp]);
      if (published) await enqueueContentEvent(tx, 'announcement', {...content, id: result.insertId, revision: 1}, 'announcement_published', timestamp);
      return result.insertId;
    });
    res.status(201).json({id});
  }));

  app.put('/api/announcements/:id', ...secure, wrap(async (req, res) => {
    const id = contentId(req.params.id);
    await ctx.getPool().transaction(async tx => {
      const [rows] = await tx.execute('SELECT * FROM announcements WHERE id = ? FOR UPDATE', [id]);
      const old: AnnouncementRow = rows[0];
      if (!old) throw new ContentError('公告不存在', 404);
      checkRevision(old, req.body);
      const content = commonContent(req.body, old);
      await tx.execute('UPDATE announcements SET title = ?, body = ?, pinned = ?, channels = ?, revision = revision + 1, updated_ms = ? WHERE id = ?',
        [content.title, content.body, contentBoolean(req.body.pinned, !!old.pinned), content.channels, now(), id]);
    });
    res.json({success: true});
  }));

  app.post('/api/announcements/:id/:action', ...secure, wrap(async (req, res) => {
    const id = contentId(req.params.id);
    const action = req.params.action;
    if (!['publish', 'withdraw', 'archive'].includes(action)) throw new ContentError('操作不存在', 404);
    await ctx.getPool().transaction(async tx => {
      const [rows] = await tx.execute('SELECT * FROM announcements WHERE id = ? FOR UPDATE', [id]);
      const row: AnnouncementRow = rows[0];
      if (!row) throw new ContentError('公告不存在', 404);
      checkRevision(row, req.body);
      if ((action === 'publish' && row.state === 'published') ||
          (action !== 'publish' && row.state !== 'published')) throw new ContentError('当前状态不支持此操作', 409);
      const timestamp = now();
      const state = action === 'publish' ? 'published' : action === 'archive' ? 'archived' : 'draft';
      await tx.execute('UPDATE announcements SET state = ?, published_ms = ?, revision = revision + 1, updated_ms = ? WHERE id = ?',
        [state, action === 'publish' ? timestamp : row.published_ms, timestamp, id]);
      if (action === 'publish') await enqueueContentEvent(tx, 'announcement', {...row, revision: Number(row.revision) + 1}, 'announcement_published', timestamp);
    });
    res.json({success: true});
  }));

  app.delete('/api/announcements/:id', ...secure, wrap(async (req, res) => {
    const id = contentId(req.params.id);
    const [result] = await ctx.getPool().execute("DELETE FROM announcements WHERE id = ? AND state = 'draft' AND revision = ?", [id, Number(req.body.revision)]);
    if (!result.affectedRows) throw new ContentError('只能删除未变化的草稿，请刷新后重试', 409);
    res.json({success: true});
  }));

  for (const publicView of [false, true]) {
    app.get(publicView ? '/api/public/maintenances' : '/api/maintenances',
      ...(!publicView ? secure : []), wrap(async (req, res) => {
        const timestamp = now();
        const page = pageNumber(req);
        const past = req.query.history === '1';
        const db = ctx.getPool();
        const historyFilter = past ? '(w.cancelled_ms IS NOT NULL OR (w.ends_ms IS NOT NULL AND w.ends_ms <= ?))'
          : '(w.cancelled_ms IS NULL AND (w.ends_ms IS NULL OR w.ends_ms > ?))';
        const [rows]: [MaintenanceRow[], unknown] = await db.execute(`SELECT w.* FROM maintenances w
          WHERE ${historyFilter} ${publicView ? `AND w.is_public = 1 AND EXISTS (SELECT 1 FROM maintenance_monitors mm
            JOIN monitors m ON m.id = mm.monitor_id WHERE mm.maintenance_id = w.id AND m.is_public = 1)` : ''}
          ORDER BY w.starts_ms ${past ? 'DESC' : 'ASC'}, w.id DESC LIMIT 21 OFFSET ${(page - 1) * 20}`, [timestamp]);
        const visible = rows.slice(0, 20);
        const ids = visible.map(row => row.id);
        const [members] = ids.length ? await db.execute(`SELECT mm.maintenance_id, m.id, m.name FROM maintenance_monitors mm
          JOIN monitors m ON m.id = mm.monitor_id WHERE mm.maintenance_id IN (${ids.map(() => '?').join(',')})
          ${publicView ? 'AND m.is_public = 1' : ''} ORDER BY m.id`, ids) : [[]];
        const notifications = publicView ? [] : await deliveries(db, 'maintenance', ids);
        res.json({items: visible.map(row => ({id: row.id, title: row.title, body_html: renderContent(row.body),
          state: maintenancePhase(row, timestamp), starts_at: new Date(Number(row.starts_ms)).toISOString(),
          ends_at: row.ends_ms == null ? null : new Date(Number(row.ends_ms)).toISOString(),
          monitors: members.filter(member => member.maintenance_id === row.id).map(({id, name}) => ({id, name})),
          ...(!publicView ? {body: row.body, revision: row.revision, channels: parseChannels(row.channels),
            is_public: !!row.is_public, continue_checks: !!row.continue_checks, suppress_alerts: !!row.suppress_alerts,
            exclude_stats: !!row.exclude_stats, deliveries: notifications.filter(item => item.owner_id === row.id)} : {})})),
        page, has_more: rows.length > 20});
      }));
  }

  app.post('/api/maintenances', ...secure, wrap(async (req, res) => {
    const timestamp = now();
    const content = commonContent(req.body);
    const immediate = contentBoolean(req.body.immediate, false);
    const starts = immediate ? timestamp : contentTime(req.body.starts_at, '开始时间');
    const ends = req.body.ends_at == null || req.body.ends_at === '' ? null : contentTime(req.body.ends_at, '结束时间');
    if ((!immediate && (starts <= timestamp || ends == null)) || (ends != null && ends <= starts)) {
      throw new ContentError('预约需填写未来的起止时间，结束时间必须晚于开始时间');
    }
    const id = await ctx.getPool().transaction(async tx => {
      const ids = await validateMonitors(tx, req.body.monitor_ids);
      const [result] = await tx.execute(`INSERT INTO maintenances
        (title, body, starts_ms, ends_ms, continue_checks, suppress_alerts, exclude_stats, is_public, channels, phase, created_ms, updated_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [content.title, content.body, starts, ends, contentBoolean(req.body.continue_checks, true),
        contentBoolean(req.body.suppress_alerts, true), contentBoolean(req.body.exclude_stats, true),
        contentBoolean(req.body.is_public, false), content.channels, immediate ? 'active' : 'scheduled', timestamp, timestamp]);
      for (const monitorId of ids) await tx.execute('INSERT INTO maintenance_monitors (maintenance_id, monitor_id) VALUES (?, ?)', [result.insertId, monitorId]);
      if (immediate) for (const monitorId of ids) await syncMonitorMaintenance(tx, monitorId, timestamp);
      await enqueueContentEvent(tx, 'maintenance', {...content, id: result.insertId, revision: 1, starts_ms: starts, ends_ms: ends},
        immediate ? 'maintenance_started' : 'maintenance_scheduled', timestamp);
      return result.insertId;
    });
    res.status(201).json({id});
  }));

  app.put('/api/maintenances/:id', ...secure, wrap(async (req, res) => {
    const id = contentId(req.params.id);
    await ctx.getPool().transaction(async tx => {
      const [rows] = await tx.execute('SELECT * FROM maintenances WHERE id = ? FOR UPDATE', [id]);
      const old: MaintenanceRow = rows[0];
      if (!old) throw new ContentError('维护不存在', 404);
      checkRevision(old, req.body);
      const timestamp = now();
      const phase = maintenancePhase(old, timestamp);
      if (!['scheduled', 'active'].includes(phase)) throw new ContentError('已结束或取消的维护不可修改', 409);
      const content = commonContent(req.body, old);
      const starts = req.body.starts_at === undefined ? Number(old.starts_ms) : contentTime(req.body.starts_at, '开始时间');
      const ends = req.body.ends_at === undefined ? (old.ends_ms == null ? null : Number(old.ends_ms))
        : req.body.ends_at == null || req.body.ends_at === '' ? null : contentTime(req.body.ends_at, '结束时间');
      if ((phase === 'scheduled' && (starts <= timestamp || ends == null)) || (ends != null && ends <= Math.max(starts, timestamp))) {
        throw new ContentError('结束时间必须在未来且晚于开始时间；预约需保留起止时间');
      }
      const flags = ['continue_checks', 'suppress_alerts', 'exclude_stats'] as const;
      const options = flags.map(key => contentBoolean(req.body[key], !!old[key]));
      const [members] = await tx.execute('SELECT monitor_id FROM maintenance_monitors WHERE maintenance_id = ? ORDER BY monitor_id', [id]);
      const previousIds = members.map(member => Number(member.monitor_id));
      const ids = req.body.monitor_ids === undefined ? previousIds : await validateMonitors(tx, req.body.monitor_ids);
      if (phase === 'active' && (starts !== Number(old.starts_ms) || flags.some((key, index) => options[index] !== Number(old[key])) ||
          JSON.stringify(ids) !== JSON.stringify(previousIds))) throw new ContentError('已开始的维护不可修改监控范围、开始时间或处理开关', 409);
      const revision = Number(old.revision) + 1;
      await tx.execute(`UPDATE maintenances SET title = ?, body = ?, starts_ms = ?, ends_ms = ?,
        continue_checks = ?, suppress_alerts = ?, exclude_stats = ?, is_public = ?, channels = ?, revision = ?, updated_ms = ? WHERE id = ?`,
      [content.title, content.body, starts, ends, ...options, contentBoolean(req.body.is_public, !!old.is_public), content.channels, revision, timestamp, id]);
      if (phase === 'scheduled') {
        await tx.execute('DELETE FROM maintenance_monitors WHERE maintenance_id = ?', [id]);
        for (const monitorId of ids) await tx.execute('INSERT INTO maintenance_monitors (maintenance_id, monitor_id) VALUES (?, ?)', [id, monitorId]);
      }
      if (starts !== Number(old.starts_ms) || ends !== (old.ends_ms == null ? null : Number(old.ends_ms))) {
        await enqueueContentEvent(tx, 'maintenance', {...old, ...content, starts_ms: starts, ends_ms: ends, revision}, 'maintenance_rescheduled', timestamp);
      }
    });
    res.json({success: true});
  }));

  app.post('/api/maintenances/:id/:action', ...secure, wrap(async (req, res) => {
    const id = contentId(req.params.id);
    const action = req.params.action;
    if (!['cancel', 'finish'].includes(action)) throw new ContentError('操作不存在', 404);
    await ctx.getPool().transaction(async tx => {
      const [rows] = await tx.execute('SELECT * FROM maintenances WHERE id = ? FOR UPDATE', [id]);
      const row: MaintenanceRow = rows[0];
      if (!row) throw new ContentError('维护不存在', 404);
      checkRevision(row, req.body);
      const timestamp = now();
      const phase = maintenancePhase(row, timestamp);
      if ((action === 'cancel' && phase !== 'scheduled') || (action === 'finish' && phase !== 'active')) {
        throw new ContentError('当前状态不支持此操作，请刷新后重试', 409);
      }
      const next = {...row, revision: Number(row.revision) + 1,
        ends_ms: action === 'finish' ? timestamp : row.ends_ms};
      await tx.execute('UPDATE maintenances SET ends_ms = ?, cancelled_ms = ?, phase = ?, revision = ?, updated_ms = ? WHERE id = ?',
        [next.ends_ms, action === 'cancel' ? timestamp : null, action === 'cancel' ? 'cancelled' : 'completed', next.revision, timestamp, id]);
      await enqueueContentEvent(tx, 'maintenance', next, action === 'cancel' ? 'maintenance_cancelled' : 'maintenance_completed', timestamp);
    });
    res.json({success: true});
  }));
}
