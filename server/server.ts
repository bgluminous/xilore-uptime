import express, { type Request, type Response, type NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { pathToFileURL } from 'url';
import type { Server } from 'http';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { getLogger } from 'xilore-log4js';
import { connectDatabase, initializeTables, testDatabaseConnection, validateExistingDatabase } from './core/database.js';
import { execQuery } from './core/db-utils.js';
import { escapeHtml } from './core/templates.js';
import { dispatchMonitorNotification } from './features/notifications.js';
import {createMonitorRunner} from './features/monitor-runner.js';
import {createMaintenanceCoordinator, decorateMaintenance, loadMaintenanceIntervals, loadOverviewStats} from './features/maintenance.js';
import {registerCommunicationRoutes} from './routes/communications.js';
import { buildStatusBars24h } from './features/status-bars.js';
import { buildHistoryChart, HISTORY_RANGE_CONFIG } from './features/history-chart.js';
import { calculateResponseStats, loadResponseStats24h } from './features/response-stats.js';
import { registerGroupRoutes } from './routes/groups.js';
import { registerSettingsRoutes } from './routes/settings.js';
import { registerPublicRoutes } from './routes/public.js';
import { registerVersionRoutes } from './routes/version.js';
import type {
  MonitorRow,
  UptimeAggRow
} from './core/db-types.js';
import type { DatabaseClient } from './core/db-utils.js';
import { assertWritable, initializeRuntimeMode, isUiDevMode, uiDevModeMiddleware } from './core/runtime-mode.js';

declare global {
  namespace Express {
    interface Request {
      user?: { id: number; username: string; role: string };
    }
  }
}

const app = express();
const PORT = (process.env.PORT as string) || '3000';
const CONFIG_PATH = process.env.CONFIG_PATH || path.join(process.cwd(), 'data', 'config.json');

interface AppConfig {
  database?: { host: string; port?: number; user: string; password: string; name: string };
  jwtSecret?: string;
  installed?: boolean;
  installedAt?: string;
  uiDevMode?: boolean;
}

let pool: DatabaseClient | null = null;
let config: AppConfig | null = null;
let cleanupTimeout: ReturnType<typeof setTimeout> | null = null;
let cleanupInterval: ReturnType<typeof setInterval> | null = null;

// ============ 日志（xilore-log4js） ============
const logger = getLogger('server');

function logRequest(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    const msg = `${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`;
    const data = { ip: req.ip || req.socket?.remoteAddress, userAgent: req.get('user-agent') };
    const full = `${msg} ${JSON.stringify(data)}`;
    if (res.statusCode >= 400) logger.error(full);
    else if (res.statusCode >= 300) logger.warn(full);
    else logger.info(full);
  });

  next();
}

// ============ 中间件 ============
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());
app.use(logRequest);
app.use(uiDevModeMiddleware);

// 在所有路由之前应用初始化检查中间件
app.use(initCheckMiddleware);

// ============ 配置管理 ============
function loadConfig(): boolean {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8')) as AppConfig;
      if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('配置格式错误');
      logger.info('配置文件加载成功');
      return true;
    } else {
      logger.info('配置文件不存在，等待初始化');
    }
  } catch (e) {
    // 配置无法解析时无法确定保护开关，必须停止启动，且不输出可能含凭据的原文。
    throw new Error('加载配置失败，请检查 CONFIG_PATH 指向的 JSON 配置文件');
  }
  return false;
}

function saveConfig(newConfig: AppConfig): void {
  assertWritable();
  config = newConfig;
  // 确保配置文件的目录存在
  const configDir = path.dirname(CONFIG_PATH);
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, {recursive: true});
  }
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

// 生成随机 JWT 密钥
function generateJWTSecret() {
  return crypto.randomBytes(32).toString('base64');
}

// 获取 JWT 密钥（优先级：环境变量 > config.json > 默认值）
function getJWTSecret() {
  // 优先从环境变量获取
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }

  // 从 config.json 获取
  if (config && config.jwtSecret) {
    return config.jwtSecret;
  }

  // 返回默认值（仅用于开发环境）
  return 'secret-key-change-in-production';
}

function isInstalled() {
  return Boolean(config && config.database && config.installed);
}

// 检查系统是否已初始化（检查数据库中是否有管理员用户）
async function isInitialized() {
  // 首先检查 config.json 是否存在
  if (!isInstalled()) {
    return false;
  }

  // 如果数据库连接池不存在，尝试连接
  if (!pool) {
    try {
      await connectDatabaseWrapper();
    } catch (e) {
      logger.warn(`数据库连接失败，系统未初始化 ${JSON.stringify({error: e.message})}`);
      return false;
    }
  }

  // 检查数据库中是否有管理员用户
  try {
    const [rows] = await execQuery(pool!, 'SELECT COUNT(*) as count FROM users WHERE role = ?', ['admin']);
    const adminCount = rows[0].count;
    return adminCount > 0;
  } catch (e) {
    logger.warn(`检查初始化状态失败 ${JSON.stringify({error: e.message})}`);
    return false;
  }
}

// ============ 数据库连接（已迁移到 core/database.ts）============
async function connectDatabaseWrapper() {
  if (!config || !config.database) throw new Error('数据库配置不存在');
  pool = await connectDatabase(config as import('./core/database.js').AppConfigWithDatabase);
}

// ============ 初始化检查中间件 ============
async function initCheckMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  // 允许访问初始化相关的路由和公开API（不需要初始化）
  const allowedPaths = [
    '/setup',
    '/api/install',
    '/api/public',
    '/api/version',
    '/api/auth/login',
    '/api/auth/logout'
  ];

  // 检查是否是允许的路径
  let isAllowed = allowedPaths.some(allowedPath =>
      req.path === allowedPath || req.path.startsWith(allowedPath)
  );

  // 对于静态文件，允许访问（在允许的路径检查之后）
  if (!isAllowed && req.path.match(/\.(css|js|html|svg|png|jpg|jpeg|gif|ico|woff|woff2|ttf|eot)$/i)) {
    isAllowed = true;
  }

  if (isAllowed) {
    next();
    return;
  }

  // 检查系统是否已初始化
  try {
    const initialized = await isInitialized();

    if (!initialized) {
      if (isUiDevMode()) {
        res.status(503).json({error: 'UI 开发模式无法读取已初始化的数据库，请检查连接和表结构'});
        return;
      }
      // 如果未初始化，所有路由（包括根路径）都重定向到 /setup
      // 如果是 API 请求，返回 JSON 错误
      if (req.path.startsWith('/api')) {
        res.status(400).json({error: '系统未初始化，请访问 /setup 进行初始化'});
        return;
      }

      // 如果是页面请求（包括根路径 /），重定向到 /setup
      res.redirect('/setup');
      return;
    }

    // 系统已初始化，允许继续访问
    next();
  } catch (error: unknown) {
    // 如果检查初始化状态失败，也视为未初始化
    logger.warn(`检查初始化状态失败 ${JSON.stringify({error: (error as Error).message, path: req.path})}`);
    if (isUiDevMode()) {
      res.status(503).json({error: 'UI 开发模式数据库不可用'});
      return;
    }

    if (req.path.startsWith('/api')) {
      res.status(400).json({error: '系统未初始化，请访问 /setup 进行初始化'});
      return;
    }

    res.redirect('/setup');
    return;
  }
}

// ============ 认证中间件 ============
function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    logger.warn(`未授权访问 ${JSON.stringify({path: req.path, method: req.method})}`);
    res.status(401).json({error: '未登录'});
    return;
  }

  try {
    req.user = jwt.verify(token, getJWTSecret()) as { id: number; username: string; role: string };
    next();
  } catch (e) {
    logger.warn(`Token 验证失败 ${JSON.stringify({path: req.path, error: (e as Error).message})}`);
    res.status(401).json({error: '登录已过期'});
    return;
  }
}

// ============ 安装向导路由 ============
app.get('/api/install/status', async (_req: Request, res: Response) => {
  const installed = isInstalled();
  const initialized = installed ? await isInitialized() : false;
  res.setHeader('Cache-Control', 'no-store');
  res.json({installed, initialized, uiDevMode: isUiDevMode()});
});

app.post('/api/install/test-db', async (req: Request, res: Response) => {
  // 如果系统已经初始化，拒绝测试数据库
  try {
    const initialized = await isInitialized();
    if (initialized) {
      return res.status(400).json({
        success: false,
        message: '系统已经初始化，无法重新测试数据库'
      });
    }
  } catch (error) {
    // 如果检查失败，继续执行（可能是未初始化状态）
    logger.warn(`检查初始化状态失败 ${JSON.stringify({error: error.message})}`);
  }

  const {host, port, user, password, name} = req.body;

  try {
    const {initialized, hasAdmin, adminCount} = await testDatabaseConnection({host, port, user, password, name});

    res.json({
      success: true,
      message: hasAdmin ? `数据库已初始化，发现 ${adminCount} 个管理员账户` : '数据库连接成功',
      initialized,
      hasAdmin,
      adminCount
    });
  } catch (e) {
    res.json({success: false, message: e.message});
  }
});

app.post('/api/install/complete', async (req: Request, res: Response) => {
  // 如果系统已经初始化，拒绝完成安装
  try {
    const initialized = await isInitialized();
    if (initialized) {
      return res.status(400).json({
        success: false,
        error: '系统已经初始化，无法重新安装'
      });
    }
  } catch (error) {
    // 如果检查失败，继续执行（可能是未初始化状态）
    logger.warn(`检查初始化状态失败 ${JSON.stringify({error: error.message})}`);
  }

  const {database, admin, skipAdmin} = req.body;

  if (!database) {
    return res.status(400).json({error: '缺少数据库配置'});
  }

  // 如果不跳过管理员创建，则验证管理员信息
  if (!skipAdmin) {
    if (!admin || !admin.username || !admin.password) {
      return res.status(400).json({error: '请填写管理员账户信息'});
    }

    if (admin.password.length < 6) {
      return res.status(400).json({error: '密码长度至少6位'});
    }
  }

  try {
    // 如果没有从环境变量获取到 JWT_SECRET，则生成一个
    let jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      jwtSecret = generateJWTSecret();
      logger.info('已自动生成 JWT 密钥并保存到配置文件');
    }

    // 保存配置
    saveConfig({
      database: {
        host: database.host,
        port: database.port || 3306,
        user: database.user,
        password: database.password,
        name: database.name
      },
      jwtSecret: jwtSecret,
      installed: true,
      installedAt: new Date().toISOString()
    });

    // 连接数据库
    await connectDatabaseWrapper();

    // 初始化表结构
    await initializeTables(pool);

    // 如果需要创建管理员账户
    if (!skipAdmin && admin) {
      const hashedPassword = await bcrypt.hash(admin.password, 10);
      await execQuery(pool!,
          'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
          [admin.username, hashedPassword, admin.email || null, 'admin']
      );
    }

    // 启动监控任务
    await initializeChecks();

    res.json({success: true, message: '安装完成'});
  } catch (e) {
    // 回滚配置
    try {
      if (fs.existsSync(CONFIG_PATH)) {
        const stats = fs.statSync(CONFIG_PATH);
        // 只删除文件，不删除目录（Docker 挂载卷可能是目录）
        if (stats.isFile()) {
          fs.unlinkSync(CONFIG_PATH);
        }
      }
    } catch (cleanupError) {
      // 清理失败不影响错误响应
      logger.warn(`清理配置文件失败 ${JSON.stringify({error: cleanupError.message})}`);
    }
    config = null;
    pool = null;

    res.status(500).json({error: (e as Error).message});
  }
});

// ============ 认证路由 ============
app.post('/api/auth/login', async (req: Request, res: Response) => {
  if (!isInstalled()) {
    logger.warn('登录尝试 - 系统未安装');
    return res.status(400).json({error: '系统未安装'});
  }

  const {username, password} = req.body;

  if (!username || !password) {
    logger.warn('登录尝试 - 缺少用户名或密码');
    return res.status(400).json({error: '请输入用户名和密码'});
  }

  try {
    const [rows] = await execQuery(pool!,
        'SELECT * FROM users WHERE username = ?',
        [username]
    );

    if (rows.length === 0) {
      logger.warn(`登录失败 - 用户不存在 ${JSON.stringify({username})}`);
      return res.status(401).json({error: '用户名或密码错误'});
    }

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      logger.warn(`登录失败 - 密码错误 ${JSON.stringify({username})}`);
      return res.status(401).json({error: '用户名或密码错误'});
    }

    const token = jwt.sign(
        {id: user.id, username: user.username, role: user.role},
        getJWTSecret(),
        {expiresIn: '7d'}
    );

    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'lax'
    });

    logger.info(`用户登录成功 ${JSON.stringify({username: user.username, userId: user.id, role: user.role})}`);

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } catch (e) {
    logger.error(`登录过程出错 ${JSON.stringify({username, error: e.message})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

app.post('/api/auth/logout', (_req: Request, res: Response) => {
  res.clearCookie('token');
  res.json({success: true});
});

app.get('/api/auth/me', authMiddleware, (req: Request, res: Response) => {
  res.json({user: req.user});
});

const performCheck = createMonitorRunner({getPool: () => pool!, logger});
const maintenanceCoordinator = createMaintenanceCoordinator({getPool: () => pool, check: performCheck, logger});
registerCommunicationRoutes(app, {getPool: () => pool!, authMiddleware, logger});

// ============ API 路由（需要认证）============

// ============ 分组 API ============
registerGroupRoutes(app, {getPool: () => pool!, logger, authMiddleware});

// ============ 监控 API ============
app.get('/api/monitors', authMiddleware, async (req: Request, res: Response) => {
  const endMs = Date.now();
  try {
    const [rows] = await execQuery(pool!,
      `SELECT id,
              name,
              type,
              target,
              port,
              interval_seconds,
              timeout_seconds,
              retries,
              expected_status,
              group_id,
              status,
              last_check,
              last_response_time,
              ssl_days_remaining,
              enabled,
              is_public,
              email_notification,
              webhook_notification,
              feishu_notification,
              auth_username,
              (auth_password IS NOT NULL AND auth_password <> '') AS auth_password_set
       FROM monitors
       ORDER BY group_id, created_at DESC`
    );

    // 返回基础数据和 24 小时统计，状态条仍通过独立接口异步获取。
    const ids = rows.map((m: MonitorRow) => m.id);
    const uptimeMap = new Map();
    if (ids.length > 0) {
      const inPlaceholders = ids.map(() => '?').join(',');
      const [uptimeRows] = await execQuery(pool!,
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

    const responseStats = await loadResponseStats24h(pool!, ids, endMs);
    const monitorsWithUptime = rows.map((monitor: MonitorRow) => {
      const u = uptimeMap.get(monitor.id) || {total: 0, up: 0};
      const uptime_24h = u.total > 0 ? (u.up / u.total) * 100 : null;
      return {
        ...monitor,
        auth_password_set: monitor.auth_password_set === 1 || monitor.auth_password_set === true,
        uptime_24h,
        avg_response_24h: responseStats.get(monitor.id)?.avgResponse ?? null,
        p99_response_24h: responseStats.get(monitor.id)?.p99Response ?? null
      };
    });

    res.json(await decorateMaintenance(pool!, monitorsWithUptime, false, endMs));
  } catch (e: unknown) {
    logger.error(`API 错误 ${JSON.stringify({path: req.path, method: req.method, error: (e as Error).message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

// 批量获取监控状态条数据（用于异步加载）
app.get('/api/monitors/statusbars', authMiddleware, async (req: Request, res: Response) => {
  try {
    const [rows] = await execQuery(pool!,"SELECT id FROM monitors");
    const ids = rows.map((r: MonitorRow) => Number(r.id)).filter((v: number) => Number.isFinite(v));
    if (ids.length === 0) {
      return res.json([]);
    }

    const inPlaceholders = ids.map(() => '?').join(',');
    // 一次性取回所有监控最近24小时的记录，避免 24 * N 次查询
    const [historyRows] = await execQuery(pool!,
      `SELECT monitor_id, status, checked_at, message, in_maintenance, stats_excluded
       FROM check_history
       WHERE checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         AND monitor_id IN (${inPlaceholders})
       ORDER BY monitor_id, checked_at`,
      ids
    );

    const endMs = Date.now();
    const maintenance = await loadMaintenanceIntervals(pool!, ids, endMs - 86400000, endMs);
    res.json(buildStatusBars24h(ids, historyRows, maintenance, endMs));
  } catch (e) {
    logger.error(`API 错误 ${JSON.stringify({path: req.path, method: req.method, error: e.message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

app.get('/api/monitors/:id', authMiddleware, async (req: Request, res: Response) => {
  try {
    const [rows] = await execQuery(pool!,
      `SELECT id,
              name,
              type,
              target,
              port,
              interval_seconds,
              timeout_seconds,
              retries,
              expected_status,
              group_id,
              status,
              last_check,
              last_response_time,
              ssl_days_remaining,
              enabled,
              is_public,
              email_notification,
              webhook_notification,
              feishu_notification,
              auth_username,
              (auth_password IS NOT NULL AND auth_password <> '') AS auth_password_set
       FROM monitors
       WHERE id = ?`,
      [req.params.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({error: '监控不存在'});
    }
    res.json({
      ...(await decorateMaintenance(pool!, rows))[0],
      auth_password_set: rows[0].auth_password_set === 1 || rows[0].auth_password_set === true
    });
  } catch (e) {
    logger.error(`API 错误 ${JSON.stringify({path: req.path, method: req.method, error: e.message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

app.post('/api/monitors', authMiddleware, async (req: Request, res: Response) => {
  const {
    name,
    type,
    target,
    port,
    interval_seconds,
    timeout_seconds,
    retries,
    expected_status,
    group_id,
    is_public,
    email_notification,
    webhook_notification,
    feishu_notification,
    auth_username,
    auth_password
  } = req.body;

  if (!name || !type || !target) {
    return res.status(400).json({error: '缺少必要参数'});
  }

  if (type === 'tcp' && !port) {
    return res.status(400).json({error: 'TCP 检测需要指定端口'});
  }

  // 限制重试次数 0-3
  const validRetries = Math.max(0, Math.min(3, retries || 0));
  // 期望状态码，0 表示任意 2xx
  const validExpectedStatus = expected_status !== undefined ? parseInt(expected_status) : 200;
  // Basic Auth 字段（仅 HTTP 模式使用）
  const validAuthUsername = (type === 'http' && auth_username) ? auth_username.trim() : null;
  const validAuthPassword = (type === 'http' && auth_password) ? auth_password : null;

  try {
    const [result] = await execQuery(pool!,
      'INSERT INTO monitors (name, type, target, port, interval_seconds, timeout_seconds, retries, expected_status, group_id, enabled, is_public, email_notification, webhook_notification, feishu_notification, auth_username, auth_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [name, type, target, port || null, interval_seconds || 60, timeout_seconds || 10, validRetries, validExpectedStatus, group_id || null, 1, is_public ? 1 : 0, email_notification ? 1 : 0, webhook_notification ? 1 : 0, feishu_notification ? 1 : 0, validAuthUsername, validAuthPassword]
    );

    const [rows] = await execQuery(pool!,
      `SELECT id,
              name,
              type,
              target,
              port,
              interval_seconds,
              timeout_seconds,
              retries,
              expected_status,
              group_id,
              status,
              last_check,
              last_response_time,
              enabled,
              is_public,
              email_notification,
              webhook_notification,
              feishu_notification,
              auth_username,
              (auth_password IS NOT NULL AND auth_password <> '') AS auth_password_set
       FROM monitors
       WHERE id = ?`,
      [result.insertId]
    );
    if (rows[0]) {
      startMonitorCheck(rows[0]);
    }

    logger.info(`创建监控成功 ${JSON.stringify({
      monitorId: result.insertId,
      name,
      type,
      target,
      groupId: group_id || null,
      user: req.user?.username
    })}`);

    if (rows[0]) {
      dispatchMonitorNotification({pool: pool!, logger}, {
        type: 'create',
        monitor: rows[0],
        newStatus: rows[0].status || 'unknown',
        message: `监控已创建：${rows[0].name}`
      });
    }

    res.status(201).json(rows[0] ? {
      ...rows[0],
      auth_password_set: rows[0].auth_password_set === 1 || rows[0].auth_password_set === true
    } : null);
  } catch (e) {
    logger.error(`创建监控失败 ${JSON.stringify({name, type, target, error: e.message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

app.put('/api/monitors/:id', authMiddleware, async (req: Request, res: Response) => {
  const {
    name,
    type,
    target,
    port,
    interval_seconds,
    timeout_seconds,
    retries,
    expected_status,
    group_id,
    enabled,
    is_public,
    email_notification,
    webhook_notification,
    feishu_notification,
    auth_username,
    auth_password
  } = req.body;
  const id = req.params.id;

  // 确保所有参数都不是 undefined，统一转换为 null 或有效值
  // MySQL2 不允许 undefined，必须使用 null
  const safeValue = (val: unknown) => val === undefined ? null : val;
  const safeInt = (val: unknown) => val === undefined ? null : (val !== null ? parseInt(String(val)) : null);
  const safeBool = (val: unknown) => val === undefined ? null : (val !== null ? Boolean(val) : null);

  // 限制重试次数 0-3
  const validRetries = retries !== undefined ? Math.max(0, Math.min(3, retries)) : null;
  // 期望状态码
  const validExpectedStatus = expected_status !== undefined ? parseInt(expected_status) : null;
  // group_id 可以为 null（未分组），但 undefined 表示不更新
  const validGroupId = group_id === undefined
    ? undefined  // 不更新
    : (group_id === '' || group_id === 0 || group_id === null)
      ? null  // 设为未分组
      : (typeof group_id === 'string' ? parseInt(group_id) : group_id);
  const hasAuthUsername = Object.prototype.hasOwnProperty.call(req.body, 'auth_username');
  const hasAuthPassword = Object.prototype.hasOwnProperty.call(req.body, 'auth_password');

  try {
    const [existing] = await execQuery(pool!,
      'SELECT id, type, group_id, auth_username, auth_password FROM monitors WHERE id = ?',
      [id]
    );
    if (existing.length === 0) {
      return res.status(404).json({error: '监控不存在'});
    }

    const effectiveType = (type !== undefined && type !== null) ? type : existing[0].type;

    // Basic Auth 字段：只有在 HTTP 模式下才允许；并且只有在请求体明确包含字段时才更新
    let finalAuthUsername = existing[0].auth_username;
    let finalAuthPassword = existing[0].auth_password;

    if (effectiveType !== 'http') {
      finalAuthUsername = null;
      finalAuthPassword = null;
    } else {
      if (hasAuthUsername) {
        finalAuthUsername = auth_username ? String(auth_username).trim() : null;
      }
      if (hasAuthPassword) {
        finalAuthPassword = auth_password ? String(auth_password) : null;
      }
    }

    // 如果 group_id 未提供，保持原值
    const finalGroupId = validGroupId !== undefined ? validGroupId : existing[0].group_id;

    // 确保所有参数都不是 undefined
    const params = [
      safeValue(name),
      safeValue(type),
      safeValue(target),
      safeInt(port),
      safeInt(interval_seconds),
      safeInt(timeout_seconds),
      validRetries,
      validExpectedStatus,
      finalGroupId,
      safeBool(enabled),
      is_public !== undefined ? (is_public ? 1 : 0) : null,
      email_notification !== undefined ? (email_notification ? 1 : 0) : null,
      webhook_notification !== undefined ? (webhook_notification ? 1 : 0) : null,
      feishu_notification !== undefined ? (feishu_notification ? 1 : 0) : null,
      finalAuthUsername,
      finalAuthPassword,
      id
    ];

    await execQuery(pool!,
      `UPDATE monitors
       SET name                 = COALESCE(?, name),
           type                 = COALESCE(?, type),
           target               = COALESCE(?, target),
           port                 = COALESCE(?, port),
           interval_seconds     = COALESCE(?, interval_seconds),
           timeout_seconds      = COALESCE(?, timeout_seconds),
           retries              = COALESCE(?, retries),
           expected_status      = COALESCE(?, expected_status),
           group_id             = ?,
           enabled              = COALESCE(?, enabled),
            is_public            = COALESCE(?, is_public),
            email_notification   = COALESCE(?, email_notification),
            webhook_notification = COALESCE(?, webhook_notification),
            feishu_notification  = COALESCE(?, feishu_notification),
            auth_username        = ?,
           auth_password        = ?
       WHERE id = ?`,
      params
    );

    const [rows] = await execQuery(pool!,
      `SELECT id,
              name,
              type,
              target,
              port,
              interval_seconds,
              timeout_seconds,
              retries,
              expected_status,
              group_id,
              status,
              last_check,
              last_response_time,
              ssl_days_remaining,
              enabled,
              is_public,
              email_notification,
              webhook_notification,
              feishu_notification,
              auth_username,
              (auth_password IS NOT NULL AND auth_password <> '') AS auth_password_set
       FROM monitors
       WHERE id = ?`,
      [id]
    );
    // 更新后重新启动或停止定时任务（根据 enabled 状态）
    if (rows[0]) {
      startMonitorCheck(rows[0]);
    }

    logger.info(`更新监控成功 ${JSON.stringify({
      monitorId: id,
      name: name || '未更改',
      type: type || '未更改',
      groupId: validGroupId,
      user: req.user?.username
    })}`);

    res.json(rows[0] ? {
      ...rows[0],
      auth_password_set: rows[0].auth_password_set === 1 || rows[0].auth_password_set === true
    } : null);
  } catch (e) {
    logger.error(`更新监控失败 ${JSON.stringify({monitorId: id, error: e.message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

app.delete('/api/monitors/:id', authMiddleware, async (req: Request, res: Response) => {
  const id = parseInt(req.params.id);
  try {
    // 获取监控信息用于日志
    const [monitor] = await execQuery(pool!,'SELECT * FROM monitors WHERE id = ?', [id]);
    if (monitor.length === 0) {
      return res.status(404).json({error: '监控不存在'});
    }

    if (checkIntervals.has(id)) {
      clearInterval(checkIntervals.get(id));
      checkIntervals.delete(id);
      logger.info(`停止监控任务 ${JSON.stringify({monitorId: id})}`);
    }

    // 删除监控时，同时删除相关的历史记录
    await execQuery(pool!,'DELETE FROM check_history WHERE monitor_id = ?', [id]);
    await execQuery(pool!,'DELETE FROM monitors WHERE id = ?', [id]);

    logger.info(`删除监控成功 ${JSON.stringify({
      monitorId: id,
      name: monitor[0]?.name || '未知',
      type: monitor[0]?.type || '未知',
      user: req.user?.username
    })}`);

    dispatchMonitorNotification({pool: pool!, logger}, {
      type: 'delete',
      monitor: monitor[0],
      oldStatus: monitor[0].status || 'unknown',
      message: `监控已删除：${monitor[0].name}`
    });

    res.json({success: true});
  } catch (e) {
    logger.error(`删除监控失败 ${JSON.stringify({monitorId: id, error: e.message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

app.post('/api/monitors/:id/check', authMiddleware, async (req: Request, res: Response) => {
  const id = req.params.id;
  try {
    const [rows] = await execQuery(pool!,'SELECT * FROM monitors WHERE id = ?', [id]);
    if (rows.length === 0) {
      logger.warn(`手动检测失败 - 监控不存在 ${JSON.stringify({monitorId: id, user: req.user?.username})}`);
      return res.status(404).json({error: '监控不存在'});
    }

    logger.info(`开始手动检测 ${JSON.stringify({
      monitorId: id,
      name: rows[0].name,
      target: rows[0].target,
      user: req.user?.username
    })}`);
    const result = await performCheck(rows[0]);
    if (result.skipped) return res.status(409).json({error: result.message, code: 'MAINTENANCE_CHECKS_PAUSED'});
    logger.info(`手动检测完成 ${JSON.stringify({
      monitorId: id,
      name: rows[0].name,
      status: result.status,
      responseTime: result.responseTime,
      user: req.user?.username
    })}`);

    res.json(result);
  } catch (e) {
    logger.error(`手动检测失败 ${JSON.stringify({monitorId: id, error: e.message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

app.delete('/api/monitors/:id/history', authMiddleware, async (req: Request, res: Response) => {
  const id = req.params.id;
  try {
    const [rows] = await execQuery(pool!,'SELECT * FROM monitors WHERE id = ?', [id]);
    if (rows.length === 0) {
      logger.warn(`清空历史失败 - 监控不存在 ${JSON.stringify({monitorId: id, user: req.user?.username})}`);
      return res.status(404).json({error: '监控不存在'});
    }

    const [deleteResult] = await execQuery(pool!,'DELETE FROM check_history WHERE monitor_id = ?', [id]);
    logger.info(`清空监控历史成功 ${JSON.stringify({
      monitorId: id,
      name: rows[0].name,
      deletedRecords: deleteResult.affectedRows,
      user: req.user?.username
    })}`);

    res.json({success: true});
  } catch (e) {
    logger.error(`清空监控历史失败 ${JSON.stringify({monitorId: id, error: e.message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

app.delete('/api/monitors/:id/history/:historyId', authMiddleware, async (req: Request, res: Response) => {
  const monitorId = req.params.id;
  const historyId = req.params.historyId;
  try {
    // 验证监控是否存在
    const [monitorRows] = await execQuery(pool!,'SELECT * FROM monitors WHERE id = ?', [monitorId]);
    if (monitorRows.length === 0) {
      logger.warn(`删除历史记录失败 - 监控不存在 ${JSON.stringify({monitorId, historyId, user: req.user?.username})}`);
      return res.status(404).json({error: '监控不存在'});
    }

    // 验证历史记录是否存在且属于该监控
    const [historyRows] = await execQuery(pool!,'SELECT * FROM check_history WHERE id = ? AND monitor_id = ?', [historyId, monitorId]);
    if (historyRows.length === 0) {
      logger.warn(`删除历史记录失败 - 记录不存在 ${JSON.stringify({monitorId, historyId, user: req.user?.username})}`);
      return res.status(404).json({error: '历史记录不存在'});
    }

    // 删除历史记录
    await execQuery(pool!,'DELETE FROM check_history WHERE id = ? AND monitor_id = ?', [historyId, monitorId]);
    logger.info(`删除历史记录成功 ${JSON.stringify({
      monitorId,
      historyId,
      name: monitorRows[0].name,
      user: req.user?.username
    })}`);

    res.json({success: true});
  } catch (e) {
    logger.error(`删除历史记录失败 ${JSON.stringify({monitorId, historyId, error: e.message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

// 删除所有检测历史
app.delete('/api/history/all', authMiddleware, async (req: Request, res: Response) => {
  try {
    // 使用 TRUNCATE 释放表空间（比 DELETE 更适合“全清空”）
    await execQuery(pool!,'TRUNCATE TABLE check_history');
    logger.info(`清空所有检测历史成功(TRUNCATE) ${JSON.stringify({
      user: req.user?.username
    })}`);

    // TRUNCATE 不返回 affectedRows，这里统一返回 success
    res.json({success: true});
  } catch (e) {
    logger.error(`删除所有检测历史失败 ${JSON.stringify({error: e.message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

app.get('/api/monitors/:id/history', authMiddleware, async (req: Request, res: Response) => {
  const rangeParam = typeof req.query.range === 'string' ? req.query.range : '24h';
  const range = HISTORY_RANGE_CONFIG[rangeParam] ? rangeParam : '24h';
  const rangeConfig = HISTORY_RANGE_CONFIG[range];
  const {hours} = rangeConfig;
  const endMs = Date.now();
  const windowParams = [req.params.id, new Date(endMs - hours * 3600000), new Date(endMs)];

  try {
    const [monitorRows] = await execQuery(pool!, 'SELECT interval_seconds FROM monitors WHERE id = ?', [req.params.id]);

    // 计算统计信息（warning也算作可用）- 使用所有数据，不受limit限制
    const [stats] = await execQuery(pool!,
      `SELECT COUNT(*)                                           as total,
              SUM(IF(status = 'up' OR status = 'warning', 1, 0)) as up_count,
              MIN(response_time)                                 as min_response,
              MAX(response_time)                                 as max_response
       FROM check_history
       WHERE monitor_id = ?
         AND checked_at >= ? AND checked_at < ? AND stats_excluded = 0`,
      windowParams
    );

    const historyLimit = 100; // 历史记录表格显示数量（固定100条）

    // 一次性查询该时间范围内的所有历史记录（仅选择必要字段）
    const [allHistoryRows] = await execQuery(pool!,
      `SELECT status, response_time, checked_at, in_maintenance, stats_excluded
       FROM check_history
       WHERE monitor_id = ?
         AND checked_at >= ? AND checked_at < ?
       ORDER BY checked_at`,
      windowParams
    );

    const maintenance = await loadMaintenanceIntervals(pool!, [Number(req.params.id)], endMs - hours * 3600000, endMs);
    const chartData = buildHistoryChart(allHistoryRows, rangeConfig, Number(monitorRows[0]?.interval_seconds), endMs, maintenance);
    const responseStats = calculateResponseStats(allHistoryRows);

    // 获取历史记录表格数据（最近N条，按时间倒序，仅选择必要字段）
    const [historyRows] = await execQuery(pool!,
      `SELECT id, status, response_time, message, checked_at, in_maintenance, stats_excluded
       FROM check_history
       WHERE monitor_id = ?
         AND checked_at >= ? AND checked_at < ?
       ORDER BY checked_at DESC
       LIMIT ${historyLimit}`,
      windowParams
    );

    res.json({
      chartData: chartData, // 已经是按时间正序排列（从旧到新，最新在右边）
      history: historyRows,
      stats: {
        total: stats[0].total || 0,
        upCount: stats[0].up_count || 0,
        uptime: stats[0].total > 0 ? ((stats[0].up_count / stats[0].total) * 100).toFixed(2) : null,
        avgResponse: responseStats.avgResponse,
        minResponse: stats[0].min_response ?? null,
        maxResponse: stats[0].max_response ?? null,
        p99Response: responseStats.p99Response
      }
    });
  } catch (e) {
    logger.error(`获取历史记录失败 ${JSON.stringify({monitorId: req.params.id, range, error: e.message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

// ============ 设置 API ============
registerSettingsRoutes(app, {
  getPool: () => pool,
  logger,
  authMiddleware,
  setPublicPageTitleCache: (title: string) => {
    cachedPublicTitle = title;
    cachedPublicTitleAt = Date.now();
  },
  scheduleLogCleanup
});

// ============ 日志清理功能 ============
async function cleanupOldLogs() {
  if (isUiDevMode()) return;
  if (!pool) {
    return;
  }

  try {
    // 获取日志保留天数设置
    const [rows] = await execQuery(pool!,
      'SELECT value FROM settings WHERE key_name = ?',
      ['logRetentionDays']
    );

    const retentionDays = rows.length > 0 && rows[0].value
      ? parseInt(rows[0].value, 10)
      : 30;

    if (isNaN(retentionDays) || retentionDays < 30) {
      logger.warn('日志保留天数设置无效，使用默认值30天');
      return;
    }

    // 计算删除时间点
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    // 删除超过保留时间的日志
    const [result] = await execQuery(pool!,
      'DELETE FROM check_history WHERE checked_at < ?',
      [cutoffDate]
    );

    if (result.affectedRows > 0) {
      logger.info(`日志清理完成 ${JSON.stringify({
        retentionDays,
        deletedRecords: result.affectedRows,
        cutoffDate: cutoffDate.toISOString()
      })}`);
    } else {
      logger.info(`日志清理完成，无需删除记录 ${JSON.stringify({retentionDays})}`);
    }
  } catch (e) {
    logger.error(`日志清理失败 ${JSON.stringify({error: e.message})}`);
  }
}

// ============ 定时任务：每天00:00执行日志清理 ============
function scheduleLogCleanup() {
  if (isUiDevMode()) return;
  // 清除旧的定时器（如果存在）
  if (cleanupTimeout) {
    clearTimeout(cleanupTimeout);
    cleanupTimeout = null;
  }
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }

  // 计算到下一个00:00的时间
  const now = new Date();
  const nextMidnight = new Date();
  nextMidnight.setHours(24, 0, 0, 0); // 设置为明天的00:00:00

  const msUntilMidnight = nextMidnight.getTime() - now.getTime();

  logger.info(`定时任务已设置 ${JSON.stringify({
    nextCleanup: nextMidnight.toISOString(),
    msUntilMidnight
  })}`);

  // 设置第一次执行时间（到下一个00:00）
  cleanupTimeout = setTimeout(() => {
    // 立即执行一次
    cleanupOldLogs().then(_r => {
    });

    // 然后每24小时执行一次
    cleanupInterval = setInterval(() => {
      cleanupOldLogs().then(_r => {
      });
    }, 24 * 60 * 60 * 1000); // 24小时
  }, msUntilMidnight);
}

app.get('/api/stats', authMiddleware, async (req: Request, res: Response) => {
  try { res.json(await loadOverviewStats(pool!)); }
  catch { res.status(500).json({error: '统计数据读取失败'}); }
});

app.post('/api/check-all', authMiddleware, async (req: Request, res: Response) => {
  try {
    logger.info(`开始批量检测所有监控 ${JSON.stringify({user: req.user?.username})}`);
    const [monitors] = await execQuery(pool!,'SELECT * FROM monitors WHERE enabled = 1');
    const results = await Promise.all(
      monitors.map(async (monitor: MonitorRow) => {
        try {
          const result = await performCheck(monitor);
          return {id: monitor.id, name: monitor.name, ...result};
        } catch (e: unknown) {
          return {id: monitor.id, name: monitor.name, status: 'error', responseTime: 0, message: (e as Error).message};
        }
      })
    );

    logger.info(`批量检测完成 ${JSON.stringify({total: monitors.length, user: req.user?.username})}`);
    res.json(results);
  } catch (e: unknown) {
    logger.error(`批量检测失败 ${JSON.stringify({error: (e as Error).message, user: req.user?.username})}`);
    res.status(500).json({error: (e as Error).message});
  }
});

// ============ 定时检测任务 ============
const checkIntervals = new Map();
let monitorRefreshInterval: ReturnType<typeof setInterval> | undefined;

function startMonitorCheck(monitor: MonitorRow): void {
  if (isUiDevMode()) return;
  // 先清除旧的定时任务（如果存在）
  if (checkIntervals.has(monitor.id)) {
    clearInterval(checkIntervals.get(monitor.id));
    checkIntervals.delete(monitor.id);
  }

  // 如果监控是暂停的，不启动定时任务
  if (!monitor.enabled) {
    return;
  }

  const interval = setInterval(async () => {
    try {
      const [rows] = await execQuery(pool!,'SELECT * FROM monitors WHERE id = ?', [monitor.id]);
      if (rows.length > 0 && rows[0].enabled) {
        await performCheck(rows[0]);
      } else if (rows.length === 0 || !rows[0].enabled) {
        // 监控被删除或禁用，停止定时任务
        clearInterval(interval);
        checkIntervals.delete(monitor.id);
        logger.info(`监控任务已停止 ${JSON.stringify({monitorId: monitor.id, reason: rows.length === 0 ? '已删除' : '已禁用'})}`);
      }
    } catch (e) {
      logger.error(`定时检测失败 ${JSON.stringify({monitorId: monitor.id, error: e.message})}`);
    }
  }, monitor.interval_seconds * 1000);

  checkIntervals.set(monitor.id, interval);
}

async function initializeChecks() {
  if (isUiDevMode() || !pool) return;

  try {
    const [monitors] = await execQuery(pool!,'SELECT * FROM monitors WHERE enabled = 1');
    monitors.forEach(startMonitorCheck);
    maintenanceCoordinator.start();
    logger.info(`初始化监控任务 ${JSON.stringify({count: monitors.length})}`);
  } catch (e) {
    logger.error(`初始化监控任务失败 ${JSON.stringify({error: e.message})}`);
  }
}

function scheduleMonitorRefresh(): void {
  if (isUiDevMode()) return;
  monitorRefreshInterval = setInterval(async () => {
    if (isUiDevMode() || !pool) return;

    try {
      const [monitors] = await execQuery(pool!,'SELECT * FROM monitors WHERE enabled = 1');
      monitors.forEach((monitor: MonitorRow) => {
        if (!checkIntervals.has(monitor.id)) {
          startMonitorCheck(monitor);
        }
      });
    } catch (_e) {
    }
  }, 30000);
}

// ============ 公开 API（不需要认证）============
registerPublicRoutes(app, {getPool: () => pool, logger});
registerVersionRoutes(app, {logger, authMiddleware});

// ============ 页面路由（在静态文件服务之前）============
// 初始化页面
app.get('/setup', async (_req: Request, res: Response) => {
  // 如果系统已经初始化，重定向到根路径
  try {
    const initialized = await isInitialized();
    if (initialized) {
      return res.redirect('/');
    }
  } catch (error) {
    // 如果检查失败，继续显示初始化页面
    logger.warn(`检查初始化状态失败 ${JSON.stringify({error: error.message})}`);
  }

  res.sendFile(path.join(process.cwd(), 'public', 'setup.html'));
});

async function getPublicPageTitle() {
  if (!pool) return '服务状态监控';
  try {
    const [rows] = await execQuery(pool!,
      'SELECT value FROM settings WHERE key_name = ?',
      ['publicPageTitle']
    );
    const t = rows.length > 0 && rows[0].value ? String(rows[0].value) : '';
    return t.trim() || '服务状态监控';
  } catch (e) {
    return '服务状态监控';
  }
}

// 简单缓存，避免每次请求都查库
let cachedPublicTitle = null;
let cachedPublicTitleAt = 0;

async function getPublicPageTitleCached() {
  const now = Date.now();
  if (cachedPublicTitle && now - cachedPublicTitleAt < 30_000) {
    return cachedPublicTitle;
  }
  const title = await getPublicPageTitle();
  cachedPublicTitle = title;
  cachedPublicTitleAt = now;
  return title;
}

function injectTitleTag(html: string, titleText: string): string {
  const escapedDocTitle = escapeHtml(`${titleText} - Xilore Uptime`);
  return html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${escapedDocTitle}</title>`);
}

function injectPublicTitleIntoStatusHtml(html: string, publicTitle: string): string {
  const escapedTitle = escapeHtml(publicTitle);
  // 替换 <title>...</title>
  html = injectTitleTag(html, publicTitle);

  // 替换 <h1 id="public-title">...</h1>
  html = html.replace(
    /(<h1[^>]*id=["']public-title["'][^>]*>)[\s\S]*?(<\/h1>)/i,
    `$1${escapedTitle}$2`
  );

  return html;
}

// 公开展示页面 - 根路径
app.get('/', (_req: Request, res: Response) => {
  (async () => {
    const filePath = path.join(process.cwd(), 'public', 'status.html');
    const raw = fs.readFileSync(filePath, 'utf-8');
    const title = await getPublicPageTitleCached();
    const out = injectPublicTitleIntoStatusHtml(raw, title);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(out);
  })().catch((e: Error) => {
    logger.error(`渲染首页失败 ${JSON.stringify({error: e.message})}`);
    res.status(500).send('Internal Server Error');
  });
});

// 管理页面
app.get('/manage', (_req: Request, res: Response) => {
  (async () => {
    const filePath = path.join(process.cwd(), 'public', 'index.html');
    const raw = fs.readFileSync(filePath, 'utf-8');
    const title = await getPublicPageTitleCached();
    const out = injectTitleTag(raw, title);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(out);
  })().catch((e: Error) => {
    logger.error(`渲染管理页失败 ${JSON.stringify({error: e.message})}`);
    res.status(500).send('Internal Server Error');
  });
});

// ============ 静态文件服务 ============
app.use(express.static(path.join(process.cwd(), 'public'), {
  index: false // 禁用默认的 index.html，因为我们已经手动处理了路由
}));

// 其他路由统一返回 404 页面（静态/接口都未匹配时）
app.get('*', (req: Request, res: Response) => {
  try {
    const filePath = path.join(process.cwd(), 'public', '404.html');
    res.status(404).sendFile(filePath);
  } catch (e: unknown) {
    logger.error(`渲染 404 页面失败 ${JSON.stringify({error: (e as Error).message, path: req.path})}`);
    res.status(404).send('404 Not Found');
  }
});

// ============ 启动服务器 ============
export async function start(): Promise<Server> {
  loadConfig();
  initializeRuntimeMode(config?.uiDevMode);

  if (isUiDevMode()) {
    const database = config?.database;
    if (config?.installed !== true || !database ||
        !['host', 'user', 'name'].every(key => typeof database[key] === 'string' && database[key].trim()) ||
        typeof database.password !== 'string' ||
        (database.port !== undefined && (!Number.isInteger(database.port) || database.port < 1 || database.port > 65535))) {
      throw new Error('UI 开发模式要求配置有效的已有数据库，并设置 installed: true');
    }
    try {
      await connectDatabaseWrapper();
      await validateExistingDatabase(pool!);
      logger.info('UI 开发模式 · 只读：已禁用数据库修改、迁移、监控任务、历史清理和通知');
    } catch (error) {
      if (pool) await pool.end();
      pool = null;
      throw error;
    }
  } else {
    if (isInstalled()) {
      try {
        await connectDatabaseWrapper();
        await initializeTables(pool);
        await initializeChecks();
        scheduleLogCleanup();
        logger.info(`服务器启动成功 ${JSON.stringify({port: PORT})}`);
      } catch (e: unknown) {
        logger.error(`连接数据库失败 ${JSON.stringify({error: (e as Error).message})}`);
        if (pool) await pool.end();
        pool = null;
        throw e;
      }
    } else {
      logger.info('系统未安装，等待初始化设置');
    }
    scheduleMonitorRefresh();
  }

  const server = app.listen(PORT, () => {
    logger.info(`HTTP 服务器启动 ${JSON.stringify({ port: PORT })}`);
    logger.info(`Xilore UptimeBot 监控服务已启动，访问地址: http://localhost:${PORT}`);
  });
  server.once('close', () => {
    void maintenanceCoordinator.stop();
    clearInterval(monitorRefreshInterval);
    clearTimeout(cleanupTimeout);
    clearInterval(cleanupInterval);
    for (const timer of checkIntervals.values()) clearInterval(timer);
    checkIntervals.clear();
  });
  return server;
}

// 导入应用时不连接数据库或注册任务，便于使用隔离配置验证启动行为。
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  start().catch((error: Error) => {
    logger.error(`服务器启动失败 ${JSON.stringify({error: error.message, stack: error.stack})}`);
    process.exit(1);
  });
}
