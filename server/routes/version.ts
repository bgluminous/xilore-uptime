import type {Express, Request, Response, RequestHandler} from 'express';
import {readLocalVersion} from '../core/xil-version.js';
import {describeVersionQueryError, getVersionHistory, getVersionStatus, VersionQueryError} from '../features/version-query.js';

interface RouteLogger { error(message: string): void; }

export function registerVersionRoutes(app: Express, ctx: {logger: RouteLogger; authMiddleware: RequestHandler}): void {
  // 页脚只读取本机版本；匿名访问和 refresh 参数均不会触发外部请求。
  app.get('/api/version', (_req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    try { res.json(readLocalVersion()); }
    catch { res.status(500).json({error: '获取本机版本失败'}); }
  });
  app.get('/api/version/check', ctx.authMiddleware, async (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    try { res.json(await getVersionStatus(req.query.refresh === '1')); }
    catch {
      ctx.logger.error('获取版本信息失败');
      res.status(500).json({error: '获取版本信息失败'});
    }
  });
  app.get('/api/version/history', ctx.authMiddleware, async (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const page = req.query.page === undefined ? 1 : Number(req.query.page);
    if (!Number.isSafeInteger(page) || page < 1 || page > 400) {
      res.status(400).json({error: '无效的页码'});
      return;
    }
    try { res.json(await getVersionHistory(page, req.query.refresh === '1')); }
    catch (error) {
      res.status(502).json({error: error instanceof VersionQueryError ? describeVersionQueryError(error) : '更新日志暂时无法读取，请稍后重试'});
    }
  });
}
