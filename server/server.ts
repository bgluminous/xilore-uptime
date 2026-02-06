import express, { type Request, type Response, type NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import net from 'net';
import { exec } from 'child_process';
import http from 'http';
import https from 'https';
import crypto from 'crypto';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import nodemailer from 'nodemailer';
import { connectDatabase, initializeTables } from './database';
import type {
  MonitorRow,
  MonitorGroupRow,
  SettingsRow,
  CheckHistoryRow,
  UptimeAggRow
} from './db-types';
import type { Pool } from 'mysql2/promise';
import { URL } from "url";

/** mysql2 execute 返回联合类型，统一断言为 [rows|result, fields] 便于使用 */
async function execQuery(pool: Pool, sql: string, params?: any[]): Promise<[any, any]> {
  return pool.execute(sql, params || []) as Promise<[any, any]>;
}

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
}

let pool: Pool | null = null;
let config: AppConfig | null = null;
let cleanupTimeout: ReturnType<typeof setTimeout> | null = null;
let cleanupInterval: ReturnType<typeof setInterval> | null = null;

// ============ 模板渲染（邮件 HTML） ============
const TEMPLATE_DIR = path.join(process.cwd(), 'server', 'templates');
const templateCache = new Map();

function escapeHtml(input: unknown): string {
  const str = input === null || input === undefined ? '' : String(input);
  return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
}

function loadTemplate(filename: string): string {
  if (templateCache.has(filename)) return templateCache.get(filename) as string;
  const p = path.join(TEMPLATE_DIR, filename);
  const tpl = fs.readFileSync(p, 'utf-8');
  templateCache.set(filename, tpl);
  return tpl;
}

function renderTemplate(filename: string, vars: Record<string, string | number | null | undefined>): string {
  const tpl = loadTemplate(filename);
  return tpl.replace(/\{\{\s*([A-Z0-9_]+)\s*}/g, (_: string, key: string) => {
    const v = Object.prototype.hasOwnProperty.call(vars, key) ? vars[key] : '';
    return v === null || v === undefined ? '' : String(v);
  });
}

// ============ 日志工具 ============
function log(level: string, message: string, data: object | null = null): void {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;

  if (data) {
    console.log(logMessage, data);
  } else {
    console.log(logMessage);
  }
}

function logRequest(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    const statusColor = res.statusCode >= 400 ? 'ERROR' : res.statusCode >= 300 ? 'WARN' : 'INFO';
    log(statusColor, `${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`, {
      ip: req.ip || req.socket?.remoteAddress,
      userAgent: req.get('user-agent')
    });
  });

  next();
}

// ============ 中间件 ============
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());
app.use(logRequest);

// 在所有路由之前应用初始化检查中间件
app.use(initCheckMiddleware);

// ============ 配置管理 ============
function loadConfig(): boolean {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8')) as AppConfig;
      log('INFO', '配置文件加载成功');
      return true;
    } else {
      log('INFO', '配置文件不存在，等待初始化');
    }
  } catch (e) {
    log('ERROR', '加载配置失败', {error: e.message});
  }
  return false;
}

function saveConfig(newConfig: AppConfig): void {
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
  return config && config.database && config.installed;
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
      log('WARN', '数据库连接失败，系统未初始化', {error: e.message});
      return false;
    }
  }

  // 检查数据库中是否有管理员用户
  try {
    const [rows] = await execQuery(pool!, 'SELECT COUNT(*) as count FROM users WHERE role = ?', ['admin']);
    const adminCount = rows[0].count;
    return adminCount > 0;
  } catch (e) {
    log('WARN', '检查初始化状态失败', {error: e.message});
    return false;
  }
}

// ============ 数据库连接（已迁移到 database.ts）============
async function connectDatabaseWrapper() {
  if (!config || !config.database) throw new Error('数据库配置不存在');
  pool = await connectDatabase(config as import('./database').AppConfigWithDatabase);
}

// ============ 初始化检查中间件 ============
async function initCheckMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  // 允许访问初始化相关的路由和公开API（不需要初始化）
  const allowedPaths = [
    '/setup',
    '/api/install',
    '/api/public',
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
    log('WARN', '检查初始化状态失败', {error: (error as Error).message, path: req.path});

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
    log('WARN', '未授权访问', {path: req.path, method: req.method});
    res.status(401).json({error: '未登录'});
    return;
  }

  try {
    req.user = jwt.verify(token, getJWTSecret()) as { id: number; username: string; role: string };
    next();
  } catch (e) {
    log('WARN', 'Token 验证失败', {path: req.path, error: (e as Error).message});
    res.status(401).json({error: '登录已过期'});
    return;
  }
}

// ============ 安装向导路由 ============
app.get('/api/install/status', async (_req: Request, res: Response) => {
  const installed = isInstalled();
  const initialized = installed ? await isInitialized() : false;
  res.json({installed, initialized});
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
    log('WARN', '检查初始化状态失败', {error: error.message});
  }

  const {host, port, user, password, name} = req.body;

  try {
    // 先尝试连接服务器（不指定数据库）
    const testPool = mysql.createPool({
      host,
      port: port || 3306,
      user,
      password,
      waitForConnections: true,
      connectionLimit: 1
    });

    // noinspection JSVoidFunctionReturnValueUsed,ES6RedundantAwait
    const conn = await testPool.getConnection();

    // 创建数据库（如果不存在）
    await conn.query(`CREATE DATABASE IF NOT EXISTS \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);

    // 切换到目标数据库检查是否已初始化
    let initialized = false;
    let hasAdmin = false;
    let adminCount = 0;

    try {
      await conn.query(`USE \`${name}\``);

      // 检查 users 表是否存在
      const [tables] = (await conn.query(`SHOW TABLES LIKE 'users'`)) as [any[], any];
      if (Array.isArray(tables) && tables.length > 0) {
        initialized = true;
        // 检查是否存在管理员账户
        const [admins] = await conn.query(`SELECT COUNT(*) as count
                                           FROM users
                                           WHERE role = 'admin'`);
        adminCount = admins[0].count;
        hasAdmin = adminCount > 0;
      }
    } catch (e) {
      // 数据库可能是空的，忽略错误
    }

    conn.release();
    testPool.end();

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
    log('WARN', '检查初始化状态失败', {error: error.message});
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
      log('INFO', '已自动生成 JWT 密钥并保存到配置文件');
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
      log('WARN', '清理配置文件失败', {error: cleanupError.message});
    }
    config = null;
    pool = null;

    res.status(500).json({error: (e as Error).message});
  }
});

// ============ 认证路由 ============
app.post('/api/auth/login', async (req: Request, res: Response) => {
  if (!isInstalled()) {
    log('WARN', '登录尝试 - 系统未安装');
    return res.status(400).json({error: '系统未安装'});
  }

  const {username, password} = req.body;

  if (!username || !password) {
    log('WARN', '登录尝试 - 缺少用户名或密码');
    return res.status(400).json({error: '请输入用户名和密码'});
  }

  try {
    const [rows] = await execQuery(pool!,
        'SELECT * FROM users WHERE username = ?',
        [username]
    );

    if (rows.length === 0) {
      log('WARN', '登录失败 - 用户不存在', {username});
      return res.status(401).json({error: '用户名或密码错误'});
    }

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      log('WARN', '登录失败 - 密码错误', {username});
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

    log('INFO', '用户登录成功', {username: user.username, userId: user.id, role: user.role});

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } catch (e) {
    log('ERROR', '登录过程出错', {username, error: e.message});
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

// ============ 监控检测函数 ============
async function checkHttp(
    target: string,
    timeoutSeconds: number,
    expectedStatus: number = 200,
    authUsername: string | null = null,
    authPassword: string | null = null
): Promise<{ status: string; responseTime: number | null; message: string; statusCode?: number }> {
  const timeout = timeoutSeconds * 1000;
  const startTime = Date.now();
  const initialUrl = target.startsWith('http') ? target : `https://${target}`;

  // 支持跟随重定向的 HTTP 请求；优先使用 HEAD 减少流量，不支持时回退 GET
  const makeRequest = (url: string, redirectCount: number = 0, useHead: boolean = true): Promise<{
    status: string;
    responseTime: number | null;
    message: string;
    statusCode?: number
  }> => {
    return new Promise((resolve) => {
      if (redirectCount > 5) {
        resolve({
          status: 'down',
          responseTime: null,
          message: '重定向次数过多'
        });
        return;
      }

      let parsedUrl: URL;
      try {
        parsedUrl = new URL(url);
      } catch (err) {
        log('ERROR', 'URL解析失败', {url, error: err.message, redirectCount});
        resolve({
          status: 'down',
          responseTime: null,
          message: `无效的 URL: ${err.message}`
        });
        return;
      }

      const protocol = parsedUrl.protocol === 'https:' ? https : http;

      const headers = {
        'User-Agent': 'Xilore UptimeBot/1.0'
      };

      // 添加 Basic Auth 认证头
      if (authUsername && authPassword) {
        const auth = Buffer.from(`${authUsername}:${authPassword}`).toString('base64');
        headers['Authorization'] = `Basic ${auth}`;
      }

      const method = useHead ? 'HEAD' : 'GET';
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method,
        headers
      };

      const req = protocol.request(options, (res: http.IncomingMessage) => {
        const responseTime = Date.now() - startTime;

        // 处理重定向 (301, 302, 303, 307, 308)
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          res.destroy();
          // 构建重定向 URL
          let redirectUrl = res.headers.location;
          if (!redirectUrl.startsWith('http')) {
            // 相对路径重定向：确保以 / 开头
            if (!redirectUrl.startsWith('/')) {
              redirectUrl = '/' + redirectUrl;
            }
            redirectUrl = `${parsedUrl.protocol}//${parsedUrl.host}${redirectUrl}`;
          }
          // 递归跟随重定向（继续用 HEAD 以节省流量）
          resolve(makeRequest(redirectUrl, redirectCount + 1, useHead));
          return;
        }

        // HEAD 不被支持时回退到 GET（仅重试当前 URL 一次，不读 body）
        if (useHead && (res.statusCode === 405 || res.statusCode === 501)) {
          res.destroy();
          resolve(makeRequest(url, redirectCount, false));
          return;
        }

        // 检查期望状态码
        // expectedStatus 为 0 表示接受任何 2xx 状态码
        let success: boolean;
        if (expectedStatus === 0) {
          success = res.statusCode >= 200 && res.statusCode < 300;
        } else {
          success = res.statusCode === expectedStatus;
        }

        // 只有当检测成功（实际状态码匹配期望状态码）时才记录响应时间
        // 如果状态码不匹配期望值，不记录响应时间
        const shouldRecordTime = success;

        resolve({
          status: success ? 'up' : 'down',
          responseTime: shouldRecordTime ? responseTime : null,
          message: `HTTP ${res.statusCode}`,
          statusCode: res.statusCode
        });
        res.destroy();
      });

      req.on('error', (err: Error) => {
        // 网络错误（DNS解析失败、连接错误等）不记录响应时间
        resolve({
          status: 'down',
          responseTime: null,
          message: err.message
        });
      });

      req.setTimeout(timeout);
      req.on('timeout', () => {
        req.destroy();
        resolve({
          status: 'down',
          responseTime: null,
          message: '请求超时'
        });
      });

      req.end();
    });
  };

  return makeRequest(initialUrl);
}

async function checkTcp(target: string, port: number, timeoutSeconds: number): Promise<{ status: string; responseTime: number | null; message: string }> {
  const timeout = timeoutSeconds * 1000;
  return new Promise((resolve: (v: { status: string; responseTime: number | null; message: string }) => void) => {
    const startTime = Date.now();
    const socket = new net.Socket();

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      const responseTime = Date.now() - startTime;
      socket.destroy();
      resolve({
        status: 'up',
        responseTime,
        message: `端口 ${port} 开放`
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        status: 'down',
        responseTime: null,
        message: '连接超时'
      });
    });

    socket.on('error', (err: Error) => {
      socket.destroy();
      resolve({
        status: 'down',
        responseTime: null,
        message: err.message
      });
    });

    socket.connect(port, target);
  });
}

async function checkPing(target: string, timeoutSeconds: number): Promise<{ status: string; responseTime: number | null; message: string }> {
  const timeout = timeoutSeconds * 1000;
  const isWin = process.platform === 'win32';
  // 每次检测发 3 个包，至少 1 个成功即视为可用，减少单次丢包导致的误判
  const pingCount = 3;
  const cmd = isWin
    ? `ping -n ${pingCount} -w ${timeout} ${target}`
    : `ping -c ${pingCount} -W ${timeoutSeconds} ${target}`;

  return new Promise((resolve: (v: { status: string; responseTime: number | null; message: string }) => void) => {
    const startTime = Date.now();
    exec(cmd, {timeout: timeout * pingCount + 5000}, (error: { code?: string | number; signal?: string; message?: string } | null, stdout: string | Buffer, stderr: string | Buffer) => {
      const output = String(stdout || '') + String(stderr || '');
      // 1) 进程报错：超时、不可达等
      if (error) {
        const isTimeout = String(error.code) === 'ETIMEDOUT' || error.signal === 'SIGTERM' ||
          (error.message && error.message.includes('timeout'));
        resolve({
          status: 'down',
          responseTime: null,
          message: isTimeout ? 'Ping 超时' : '主机不可达'
        });
        return;
      }
      // 2) Windows：超时时仍常返回 exitCode 0，必须根据输出判断
      const timeoutOrLoss = /Request timed out|请求超时|timed out|100% loss|Lost\s*=\s*\d+\s*\(\s*100\s*%\s*\)|Received\s*=\s*0/i.test(output);
      const hasReply = /TTL=|time\s*[=<]\s*\d|时间\s*[=<]\s*\d|=\s*\d+(?:\.\d+)?\s*ms/i.test(output);
      if (timeoutOrLoss && !hasReply) {
        resolve({
          status: 'down',
          responseTime: null,
          message: 'Ping 超时'
        });
        return;
      }
      if (!hasReply) {
        resolve({
          status: 'down',
          responseTime: null,
          message: '无有效响应'
        });
        return;
      }
      // 3) 从输出中解析响应时间（取第一个成功回复的延迟）
      let pingTime = Date.now() - startTime;
      const timeMatch = output.match(/[=<](\d+)(?:\.\d+)?(?:\s*)?(?:ms|毫秒)/i) || output.match(/time\s*[=<]\s*(\d+)/i);
      if (timeMatch) {
        pingTime = parseInt(timeMatch[1], 10);
      }
      resolve({
        status: 'up',
        responseTime: pingTime,
        message: 'Ping 成功'
      });
    });
  });
}

// 发送邮件通知
async function sendEmailNotification(
  monitor: MonitorRow,
  oldStatus: string,
  newStatus: string,
  message: string,
  responseTime: number | null
): Promise<void> {
  try {
    // 获取邮件配置
    const [smtpRows] = await execQuery(pool!, 'SELECT key_name, value FROM settings WHERE key_name IN (?, ?, ?, ?, ?, ?)',
      ['smtpHost', 'smtpPort', 'smtpUser', 'smtpPassword', 'smtpFrom', 'smtpSecure']);

    if (smtpRows.length === 0 || !smtpRows.find((r: SettingsRow) => r.key_name === 'smtpHost' && r.value)) {
      log('WARN', '邮件配置未设置，跳过发送', {monitorId: monitor.id});
      return;
    }

    const config: { host?: string; port?: number; user?: string; password?: string; from?: string; secure?: boolean } = {};
    smtpRows.forEach((row: SettingsRow) => {
      const key = row.key_name;
      const value = row.value;
      if (key === 'smtpHost') config.host = value;
      else if (key === 'smtpPort') config.port = parseInt(value) || 587;
      else if (key === 'smtpUser') config.user = value;
      else if (key === 'smtpPassword') config.password = value;
      else if (key === 'smtpFrom') config.from = value;
      else if (key === 'smtpSecure') config.secure = value === '1' || value === 'true';
    });

    if (!config.host || !config.user || !config.password || !config.from) {
      log('WARN', '邮件配置不完整，跳过发送', {monitorId: monitor.id});
      return;
    }

    // 获取管理员邮箱
    const [userRows] = await execQuery(pool!, 'SELECT email FROM users WHERE role = ? LIMIT 1', ['admin']);
    if (userRows.length === 0 || !userRows[0].email) {
      log('WARN', '管理员邮箱未设置，跳过发送', {monitorId: monitor.id});
      return;
    }

    const toEmail = userRows[0].email;

    // 创建邮件传输器
    const transporter = (nodemailer as any).createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure || false,
      auth: {
        user: config.user,
        pass: config.password
      }
    });

    // 构建邮件内容
    const statusText = newStatus === 'up' ? '已恢复' : '已离线';
    const statusColor = newStatus === 'up' ? '#10b981' : '#ef4444';
    const statusBgColor = newStatus === 'up' ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)' : 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)';
    const statusIcon = newStatus === 'up' ? '✓' : '✕';
    const oldStatusText = oldStatus === 'up' ? '在线' : oldStatus === 'down' ? '离线' : '未知';
    const newStatusText = newStatus === 'up' ? '在线' : '离线';
    const checkTime = new Date().toLocaleString('zh-CN');
    const targetAddress = monitor.target + (monitor.port ? ':' + monitor.port : '');
    const typeText = monitor.type.toUpperCase();

    const subject = `${newStatus === 'up' ? '✅' : '❌'} 监控告警: ${monitor.name} ${statusText}`;

    const responseTimeText = (responseTime !== null && responseTime !== undefined)
      ? `${responseTime}ms`
      : '超时';

    const html = renderTemplate('monitor-status-email.template', {
      MONITOR_NAME: escapeHtml(monitor.name),
      STATUS_BG_COLOR: statusBgColor,
      STATUS_COLOR: statusColor,
      STATUS_ICON: escapeHtml(statusIcon),
      STATUS_TEXT: escapeHtml(statusText),
      TARGET_ADDRESS: escapeHtml(targetAddress),
      TYPE_TEXT: escapeHtml(typeText),
      OLD_STATUS_TEXT: escapeHtml(oldStatusText),
      NEW_STATUS_TEXT: escapeHtml(newStatusText),
      RESPONSE_TIME_TEXT: escapeHtml(responseTimeText),
      DETAIL_MESSAGE: escapeHtml(message || '无'),
      CHECK_TIME: escapeHtml(checkTime),
      YEAR: String(new Date().getFullYear())
    });

    // 发送邮件
    await transporter.sendMail({
      from: config.from,
      to: toEmail,
      subject: subject,
      html: html
    });

    log('INFO', '邮件通知发送成功', {monitorId: monitor.id, to: toEmail});
  } catch (error) {
    log('ERROR', '发送邮件通知失败', {monitorId: monitor.id, error: error.message});
    throw error;
  }
}

// 发送 Webhook 通知
async function sendWebhookNotification(
  monitor: MonitorRow,
  oldStatus: string,
  newStatus: string,
  message: string,
  responseTime: number | null
): Promise<void> {
  try {
    // 获取 Webhook 配置
    const [webhookRows] = await execQuery(pool!,
      'SELECT key_name, value FROM settings WHERE key_name IN (?, ?, ?)',
      ['webhookUrl', 'webhookMethod', 'webhookHeaders']
    );

    if (webhookRows.length === 0 || !webhookRows.find((r: SettingsRow) => r.key_name === 'webhookUrl' && r.value)) {
      log('WARN', 'Webhook 配置未设置，跳过发送', {monitorId: monitor.id});
      return;
    }

    const config: { url?: string; method?: string; headers?: Record<string, string> } = {};
    webhookRows.forEach((row: SettingsRow) => {
      const key = row.key_name;
      const value = row.value;
      if (key === 'webhookUrl') config.url = value;
      else if (key === 'webhookMethod') config.method = value || 'POST';
      else if (key === 'webhookHeaders') {
        try {
          config.headers = value ? JSON.parse(value) : {};
        } catch (e) {
          config.headers = {};
        }
      }
    });

    if (!config.url) {
      log('WARN', 'Webhook URL 未设置，跳过发送', {monitorId: monitor.id});
      return;
    }

    const method = (config.method || 'POST').toUpperCase();
    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': 'Xilore-Uptime/1.0',
      ...config.headers
    };

    // 构建请求体
    const payload = {
      event: 'monitor_status_changed',
      monitor: {
        id: monitor.id,
        name: monitor.name,
        type: monitor.type,
        target: monitor.target,
        port: monitor.port
      },
      status: {
        old: oldStatus || 'unknown',
        new: newStatus,
        text: newStatus === 'up' ? '在线' : '离线'
      },
      check: {
        responseTime: responseTime,
        message: message || '无',
        timestamp: new Date().toISOString(),
        time: new Date().toLocaleString('zh-CN')
      }
    };

    // 发送 Webhook 请求
    const parsedUrl = new URL(config.url!);
    const httpModule = parsedUrl.protocol === 'https:' ? require('https') : require('http');

    const requestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: method,
      headers: headers
    };

    await new Promise((resolve: (v?: void) => void, reject: (e: Error) => void) => {
      const req = httpModule.request(requestOptions, (res: http.IncomingMessage) => {
        let data = '';
        res.on('data', (chunk: Buffer | string) => {
          data += chunk;
        });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            log('INFO', 'Webhook 通知发送成功', {monitorId: monitor.id, statusCode: res.statusCode});
            resolve(undefined);
          } else {
            log('WARN', 'Webhook 通知返回非成功状态码', {
              monitorId: monitor.id,
              statusCode: res.statusCode
            });
            resolve(undefined); // 不抛出错误，只记录警告
          }
        });
      });

      req.on('error', (err: Error) => {
        log('ERROR', 'Webhook 请求失败', {monitorId: monitor.id, error: err.message});
        reject(err);
      });

      req.setTimeout(10000); // 10秒超时
      req.on('timeout', () => {
        req.destroy();
        log('ERROR', 'Webhook 请求超时', {monitorId: monitor.id});
        reject(new Error('Request timeout'));
      });

      if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        req.write(JSON.stringify(payload));
      }

      req.end();
    });

  } catch (error) {
    log('ERROR', '发送 Webhook 通知失败', {monitorId: monitor.id, error: error.message});
    throw error;
  }
}

// 单次检测
async function singleCheck(monitor: MonitorRow): Promise<{ status: string; responseTime: number | null; message: string }> {
  const timeout = monitor.timeout_seconds || 10;
  const expectedStatus = monitor.expected_status || 200;

  // 调试：打印检测参数
  log('DEBUG', '执行检测', {
    id: monitor.id,
    name: monitor.name,
    type: monitor.type,
    target: monitor.target,
    targetType: typeof monitor.target,
    timeout,
    expectedStatus
  });

  switch (monitor.type) {
    case 'http':
      return await checkHttp(monitor.target, timeout, expectedStatus, monitor.auth_username, monitor.auth_password);
    case 'tcp':
      return await checkTcp(monitor.target, monitor.port, timeout);
    case 'ping':
      return await checkPing(monitor.target, timeout);
    default:
      return {status: 'unknown', responseTime: 0, message: '未知类型'};
  }
}

// 带重试的检测
async function performCheck(monitor: MonitorRow): Promise<{ status: string; responseTime: number | null; message: string }> {
  const maxRetries = Math.min(monitor.retries || 0, 3);
  let result: { status: string; responseTime: number | null; message: string };
  let attempt = 0;
  let retryCount = 0; // 实际重试次数

  do {
    result = await singleCheck(monitor);
    if (result.status === 'up') break;
    attempt++;
    if (attempt <= maxRetries) {
      // 重试前等待1秒
      await new Promise(r => setTimeout(r, 1000));
      retryCount++; // 只有真正重试了才计数
    }
  } while (attempt <= maxRetries && result.status === 'down');

  // 如果重试后才成功，将状态标记为warning
  let historyStatus = result.status;
  if (retryCount > 0 && result.status === 'up') {
    historyStatus = 'warning';
    result.message += ` (重试 ${retryCount} 次后成功)`;
  } else if (retryCount > 0 && result.status === 'down') {
    result.message += ` (重试 ${retryCount} 次)`;
  }

  // 获取旧状态，用于检测状态变化
  const [oldMonitorRows] = await execQuery(pool!,'SELECT status FROM monitors WHERE id = ?', [monitor.id]);
  const oldStatus = oldMonitorRows.length > 0 ? oldMonitorRows[0].status : null;

  // 更新监控状态（超时时 responseTime 为 null）
  // 注意：监控状态仍然使用原始的up/down，不使用warning
  await execQuery(pool!,
    'UPDATE monitors SET status = ?, last_check = NOW(), last_response_time = ? WHERE id = ?',
    [result.status, result.responseTime || null, monitor.id]
  );

  // 检测状态变化，如果启用了邮件通知，则发送邮件
  if (monitor.email_notification && oldStatus !== result.status) {
    // 异步发送邮件，不阻塞检测流程
    sendEmailNotification(monitor, oldStatus, result.status, result.message, result.responseTime).catch((err: Error) => {
      log('ERROR', '发送邮件通知失败', {monitorId: monitor.id, error: err.message});
    });
  }

  // 检测状态变化，如果启用了 Webhook 通知，则发送 Webhook
  if (monitor.webhook_notification && oldStatus !== result.status) {
    sendWebhookNotification(monitor, oldStatus, result.status, result.message, result.responseTime).catch((err: Error) => {
      log('ERROR', '发送 Webhook 通知失败', {monitorId: monitor.id, error: err.message});
    });
  }

  // 记录历史（超时时 responseTime 为 null）
  // 如果重试后才成功，历史记录中使用warning状态
  await execQuery(pool!,
    'INSERT INTO check_history (monitor_id, status, response_time, message) VALUES (?, ?, ?, ?)',
    [monitor.id, historyStatus, result.responseTime || null, result.message]
  );

  // 清理旧历史记录（保留最近7天）
  const [cleanupResult] = await execQuery(pool!,
    'DELETE FROM check_history WHERE monitor_id = ? AND checked_at < DATE_SUB(NOW(), INTERVAL 7 DAY)',
    [monitor.id]
  );

  // 记录检测结果（仅在状态变化或错误时记录详细信息）
  if (result.status === 'down' || cleanupResult.affectedRows > 0) {
    log('INFO', '监控检测完成', {
      monitorId: monitor.id,
      name: monitor.name,
      status: result.status,
      responseTime: result.responseTime,
      message: result.message,
      cleanedRecords: cleanupResult.affectedRows
    });
  }

  return result;
}

// ============ API 路由（需要认证）============

// ============ 分组 API ============
app.get('/api/groups', authMiddleware, async (req: Request, res: Response) => {
  try {
    const [rows] = await execQuery(pool!,'SELECT id, name, sort_order FROM monitor_groups ORDER BY sort_order, id');
    res.json(rows.map((r: MonitorGroupRow) => ({
      id: r.id,
      name: r.name,
      sort_order: r.sort_order ?? 0
    })));
  } catch (e: unknown) {
    log('ERROR', 'API 错误', {path: req.path, method: req.method, error: (e as Error).message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

app.post('/api/groups', authMiddleware, async (req: Request, res: Response) => {
  const {name, description} = req.body;

  if (!name) {
    log('WARN', '创建分组失败 - 名称为空', {user: req.user?.username});
    return res.status(400).json({error: '分组名称不能为空'});
  }

  try {
    // 检查名称是否已存在
    const [existing] = await execQuery(pool!,
      'SELECT id FROM monitor_groups WHERE name = ?',
      [name]
    );

    if (existing.length > 0) {
      log('WARN', '创建分组失败 - 名称重复', {name, user: req.user?.username});
      return res.status(400).json({error: '分组名称已存在'});
    }

    const [maxRows] = await execQuery(pool!,'SELECT COALESCE(MAX(sort_order), 0) AS max_order FROM monitor_groups');
    const nextOrder = (maxRows[0]?.max_order || 0) + 1;
    const [result] = await execQuery(pool!,
      'INSERT INTO monitor_groups (name, description, sort_order) VALUES (?, ?, ?)',
      [name, description || null, nextOrder]
    );
    log('INFO', '创建分组成功', {groupId: result.insertId, name, user: req.user?.username});
    // 返回最小必要字段
    res.json({id: result.insertId, name, sort_order: nextOrder});
  } catch (e) {
    log('ERROR', '创建分组失败', {name, error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

app.put('/api/groups/:id', authMiddleware, async (req: Request, res: Response) => {
  const {name, description, sort_order} = req.body;
  const id = req.params.id;

  try {
    // 如果提供了名称，检查是否与其他分组重复（排除当前分组）
    if (name !== undefined && name !== null) {
      const [existing] = await execQuery(pool!,
        'SELECT id FROM monitor_groups WHERE name = ? AND id != ?',
        [name, id]
      );

      if (existing.length > 0) {
        log('WARN', '更新分组失败 - 名称重复', {groupId: id, name, user: req.user?.username});
        return res.status(400).json({error: '分组名称已存在'});
      }
    }

    // 构建更新语句
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
      // 没有任何更新
      const [group] = await execQuery(pool!,'SELECT id, name, sort_order FROM monitor_groups WHERE id = ?', [id]);
      return res.json(group[0] ? {
        id: group[0].id,
        name: group[0].name,
        sort_order: group[0].sort_order ?? 0
      } : null);
    }

    values.push(id);
    await execQuery(pool!,
      `UPDATE monitor_groups
       SET ${updates.join(', ')}
       WHERE id = ?`,
      values
    );

    // 返回更新后的分组信息
    const [updated] = await execQuery(pool!,'SELECT id, name, sort_order FROM monitor_groups WHERE id = ?', [id]);

    log('INFO', '更新分组成功', {groupId: id, name, sort_order, user: req.user?.username});
    res.json(updated[0] ? {
      id: updated[0].id,
      name: updated[0].name,
      sort_order: updated[0].sort_order ?? 0
    } : null);
  } catch (e) {
    log('ERROR', '更新分组失败', {groupId: id, error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

app.delete('/api/groups/:id', authMiddleware, async (req: Request, res: Response) => {
  const id = req.params.id;

  try {
    // 将该分组下的监控移到"未分组"
    const [updateResult] = await execQuery(pool!,'UPDATE monitors SET group_id = NULL WHERE group_id = ?', [id]);
    await execQuery(pool!,'DELETE FROM monitor_groups WHERE id = ?', [id]);
    log('INFO', '删除分组成功', {
      groupId: id,
      affectedMonitors: updateResult.affectedRows,
      user: req.user?.username
    });
    res.json({success: true});
  } catch (e) {
    log('ERROR', '删除分组失败', {groupId: id, error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

// ============ 监控 API ============
function buildStatusBars24h(monitorIds: number[], historyRows: CheckHistoryRow[]): { monitorId: number; statusBar24h: any[] }[] {
  const now = new Date();
  const endMs = now.getTime();
  const oneHourMs = 60 * 60 * 1000;
  const segmentMs = 5 * 60 * 1000; // 12 个 5 分钟段
  const start24hMs = endMs - 24 * oneHourMs;

  const bucketsByMonitor = new Map();
  for (const id of monitorIds) {
    bucketsByMonitor.set(id, Array.from({length: 24}, () => []));
  }

  for (const row of historyRows) {
    // 兼容 MySQL 返回 string 的情况，统一转 number 做 Map key
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

  const priority = {down: 3, warning: 2, up: 1};

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
        if (!current || priority[r.status] > priority[current]) {
          segments[segIdx] = r.status;
        }

        if (r.status === "up") {
          upChecks++;
          lastUp = r;
        } else if (r.status === "down") {
          downChecks++;
          lastDown = r;
        } else if (r.status === "warning") {
          warningChecks++;
          lastWarning = r;
        }
      }

      // 向前填充空缺（使用最近一次状态），避免检测间隔大时出现灰块
      let lastKnown = null;
      for (let i = 0; i < segments.length; i++) {
        if (segments[i]) {
          lastKnown = segments[i];
        } else if (lastKnown) {
          segments[i] = lastKnown;
        }
      }

      // 向后填充开头空缺（使用最早一次状态）
      const firstKnownIndex = segments.findIndex((s) => s !== null);
      if (firstKnownIndex > 0) {
        for (let i = 0; i < firstKnownIndex; i++) {
          segments[i] = segments[firstKnownIndex];
        }
      }

      const totalChecks = records.length;
      const uptime = totalChecks > 0 ? ((upChecks + warningChecks) / totalChecks) * 100 : null;
      const status = downChecks > 0 ? "down" : warningChecks > 0 ? "warning" : upChecks > 0 ? "up" : null;

      // tooltip 详情优先展示 down，其次 warning，再其次 up（取最后一次）
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
        downChecks,
        warningChecks,
        uptime,
        segments,
      };
    });

    return {monitorId: id, statusBar24h};
  });
}

app.get('/api/monitors', authMiddleware, async (req: Request, res: Response) => {
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
              enabled,
              is_public,
              email_notification,
              webhook_notification,
              auth_username,
              (auth_password IS NOT NULL AND auth_password <> '') AS auth_password_set
       FROM monitors
       ORDER BY group_id, created_at DESC`
    );

    // 只返回基础数据和可用率，不包含状态条（状态条通过 /api/monitors/statusbars 接口获取）
    const ids = rows.map((m: MonitorRow) => m.id);
    const uptimeMap = new Map();
    if (ids.length > 0) {
      const inPlaceholders = ids.map(() => '?').join(',');
      const [uptimeRows] = await execQuery(pool!,
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
      return {
        ...monitor,
        auth_password_set: monitor.auth_password_set === 1 || monitor.auth_password_set === true,
        uptime_24h
      };
    });

    res.json(monitorsWithUptime);
  } catch (e: unknown) {
    log('ERROR', 'API 错误', {path: req.path, method: req.method, error: (e as Error).message, user: req.user?.username});
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
      `SELECT monitor_id, status, checked_at, message
       FROM check_history
       WHERE checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         AND monitor_id IN (${inPlaceholders})
       ORDER BY monitor_id, checked_at`,
      ids
    );

    res.json(buildStatusBars24h(ids, historyRows));
  } catch (e) {
    log('ERROR', 'API 错误', {path: req.path, method: req.method, error: e.message, user: req.user?.username});
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
              enabled,
              is_public,
              email_notification,
              webhook_notification,
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
      ...rows[0],
      auth_password_set: rows[0].auth_password_set === 1 || rows[0].auth_password_set === true
    });
  } catch (e) {
    log('ERROR', 'API 错误', {path: req.path, method: req.method, error: e.message, user: req.user?.username});
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
      'INSERT INTO monitors (name, type, target, port, interval_seconds, timeout_seconds, retries, expected_status, group_id, enabled, is_public, email_notification, webhook_notification, auth_username, auth_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [name, type, target, port || null, interval_seconds || 60, timeout_seconds || 10, validRetries, validExpectedStatus, group_id || null, 1, is_public ? 1 : 0, email_notification ? 1 : 0, webhook_notification ? 1 : 0, validAuthUsername, validAuthPassword]
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
              auth_username,
              (auth_password IS NOT NULL AND auth_password <> '') AS auth_password_set
       FROM monitors
       WHERE id = ?`,
      [result.insertId]
    );
    if (rows[0]) {
      startMonitorCheck(rows[0]);
    }

    log('INFO', '创建监控成功', {
      monitorId: result.insertId,
      name,
      type,
      target,
      groupId: group_id || null,
      user: req.user?.username
    });

    res.status(201).json(rows[0] ? {
      ...rows[0],
      auth_password_set: rows[0].auth_password_set === 1 || rows[0].auth_password_set === true
    } : null);
  } catch (e) {
    log('ERROR', '创建监控失败', {name, type, target, error: e.message, user: req.user?.username});
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
              enabled,
              is_public,
              email_notification,
              webhook_notification,
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

    log('INFO', '更新监控成功', {
      monitorId: id,
      name: name || '未更改',
      type: type || '未更改',
      groupId: validGroupId,
      user: req.user?.username
    });

    res.json(rows[0] ? {
      ...rows[0],
      auth_password_set: rows[0].auth_password_set === 1 || rows[0].auth_password_set === true
    } : null);
  } catch (e) {
    log('ERROR', '更新监控失败', {monitorId: id, error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

app.delete('/api/monitors/:id', authMiddleware, async (req: Request, res: Response) => {
  const id = parseInt(req.params.id);
  try {
    // 获取监控信息用于日志
    const [monitor] = await execQuery(pool!,'SELECT name, type, target FROM monitors WHERE id = ?', [id]);

    if (checkIntervals.has(id)) {
      clearInterval(checkIntervals.get(id));
      checkIntervals.delete(id);
      log('INFO', '停止监控任务', {monitorId: id});
    }

    // 删除监控时，同时删除相关的历史记录
    await execQuery(pool!,'DELETE FROM check_history WHERE monitor_id = ?', [id]);
    await execQuery(pool!,'DELETE FROM monitors WHERE id = ?', [id]);

    log('INFO', '删除监控成功', {
      monitorId: id,
      name: monitor[0]?.name || '未知',
      type: monitor[0]?.type || '未知',
      user: req.user?.username
    });

    res.json({success: true});
  } catch (e) {
    log('ERROR', '删除监控失败', {monitorId: id, error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

app.post('/api/monitors/:id/check', authMiddleware, async (req: Request, res: Response) => {
  const id = req.params.id;
  try {
    const [rows] = await execQuery(pool!,'SELECT * FROM monitors WHERE id = ?', [id]);
    if (rows.length === 0) {
      log('WARN', '手动检测失败 - 监控不存在', {monitorId: id, user: req.user?.username});
      return res.status(404).json({error: '监控不存在'});
    }

    log('INFO', '开始手动检测', {
      monitorId: id,
      name: rows[0].name,
      target: rows[0].target,
      user: req.user?.username
    });
    const result = await performCheck(rows[0]);
    log('INFO', '手动检测完成', {
      monitorId: id,
      name: rows[0].name,
      status: result.status,
      responseTime: result.responseTime,
      user: req.user?.username
    });

    res.json(result);
  } catch (e) {
    log('ERROR', '手动检测失败', {monitorId: id, error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

app.delete('/api/monitors/:id/history', authMiddleware, async (req: Request, res: Response) => {
  const id = req.params.id;
  try {
    const [rows] = await execQuery(pool!,'SELECT * FROM monitors WHERE id = ?', [id]);
    if (rows.length === 0) {
      log('WARN', '清空历史失败 - 监控不存在', {monitorId: id, user: req.user?.username});
      return res.status(404).json({error: '监控不存在'});
    }

    const [deleteResult] = await execQuery(pool!,'DELETE FROM check_history WHERE monitor_id = ?', [id]);
    log('INFO', '清空监控历史成功', {
      monitorId: id,
      name: rows[0].name,
      deletedRecords: deleteResult.affectedRows,
      user: req.user?.username
    });

    res.json({success: true});
  } catch (e) {
    log('ERROR', '清空监控历史失败', {monitorId: id, error: e.message, user: req.user?.username});
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
      log('WARN', '删除历史记录失败 - 监控不存在', {monitorId, historyId, user: req.user?.username});
      return res.status(404).json({error: '监控不存在'});
    }

    // 验证历史记录是否存在且属于该监控
    const [historyRows] = await execQuery(pool!,'SELECT * FROM check_history WHERE id = ? AND monitor_id = ?', [historyId, monitorId]);
    if (historyRows.length === 0) {
      log('WARN', '删除历史记录失败 - 记录不存在', {monitorId, historyId, user: req.user?.username});
      return res.status(404).json({error: '历史记录不存在'});
    }

    // 删除历史记录
    await execQuery(pool!,'DELETE FROM check_history WHERE id = ? AND monitor_id = ?', [historyId, monitorId]);
    log('INFO', '删除历史记录成功', {
      monitorId,
      historyId,
      name: monitorRows[0].name,
      user: req.user?.username
    });

    res.json({success: true});
  } catch (e) {
    log('ERROR', '删除历史记录失败', {monitorId, historyId, error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

// 删除所有检测历史
app.delete('/api/history/all', authMiddleware, async (req: Request, res: Response) => {
  try {
    // 使用 TRUNCATE 释放表空间（比 DELETE 更适合“全清空”）
    await execQuery(pool!,'TRUNCATE TABLE check_history');
    log('INFO', '清空所有检测历史成功(TRUNCATE)', {
      user: req.user?.username
    });

    // TRUNCATE 不返回 affectedRows，这里统一返回 success
    res.json({success: true});
  } catch (e) {
    log('ERROR', '删除所有检测历史失败', {error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

app.get('/api/monitors/:id/history', authMiddleware, async (req: Request, res: Response) => {
  const range = req.query.range || '24h'; // 1h, 24h, 7d, 30d

  // 计算时间范围
  let hours = 24;
  switch (range) {
    case '1h':
      hours = 1;
      break;
    case '24h':
      hours = 24;
      break;
    case '7d':
      hours = 24 * 7;
      break;
    case '30d':
      hours = 24 * 30;
      break;
  }

  try {
    // 计算统计信息（warning也算作可用）- 使用所有数据，不受limit限制
    const [stats] = await execQuery(pool!,
      `SELECT COUNT(*)                                           as total,
              SUM(IF(status = 'up' OR status = 'warning', 1, 0)) as up_count,
              AVG(response_time)                                 as avg_response,
              MIN(response_time)                                 as min_response,
              MAX(response_time)                                 as max_response
       FROM check_history
       WHERE monitor_id = ?
         AND checked_at >= DATE_SUB(NOW(), INTERVAL ${hours} HOUR)`,
      [req.params.id]
    );

    // 根据时间范围决定聚合间隔和图表数据点数量
    let intervalMinutes = 1; // 聚合间隔（分钟）
    let chartPoints = 60; // 图表数据点数量
    let historyLimit = 100; // 历史记录表格显示数量（固定100条）

    switch (range) {
      case '1h':
        intervalMinutes = 1; // 1分钟一个点
        chartPoints = 60;
        break;
      case '24h':
        intervalMinutes = 30; // 30分钟一个点
        chartPoints = 48;
        break;
      case '7d':
        intervalMinutes = 180; // 3小时一个点
        chartPoints = 56;
        break;
      case '30d':
        intervalMinutes = 720; // 12小时一个点
        chartPoints = 60;
        break;
    }

    // 一次性查询该时间范围内的所有历史记录（仅选择必要字段）
    const [allHistoryRows] = await execQuery(pool!,
      `SELECT status, response_time, checked_at
       FROM check_history
       WHERE monitor_id = ?
         AND checked_at >= DATE_SUB(NOW(), INTERVAL ${hours} HOUR)
       ORDER BY checked_at`,
      [req.params.id]
    );

    // 在内存中按时间段聚合数据
    const now = new Date();
    const chartData = [];
    const intervalMs = intervalMinutes * 60 * 1000;

    // 从最早的时间开始，向前生成时间段
    for (let i = chartPoints - 1; i >= 0; i--) {
      const segmentEnd = new Date(now.getTime() - i * intervalMs);
      const segmentStart = new Date(segmentEnd.getTime() - intervalMs);

      // 筛选该时间段内的记录
      const segmentRecords = allHistoryRows.filter((record: CheckHistoryRow) => {
        const recordTime = new Date(record.checked_at);
        return recordTime >= segmentStart && recordTime < segmentEnd;
      });

      if (segmentRecords.length > 0) {
        // 聚合该时间段的数据
        let totalResponseTime = 0;
        let responseTimeCount = 0;
        let minResponseTime: number | null = null;
        let maxResponseTime: number | null = null;
        let downCount = 0;
        let warningCount = 0;
        let upCount = 0;

        segmentRecords.forEach((record: CheckHistoryRow) => {
          if (record.response_time !== null && record.response_time !== undefined) {
            totalResponseTime += record.response_time;
            responseTimeCount++;
            if (minResponseTime === null || record.response_time < minResponseTime) {
              minResponseTime = record.response_time;
            }
            if (maxResponseTime === null || record.response_time > maxResponseTime) {
              maxResponseTime = record.response_time;
            }
          }

          if (record.status === 'down') {
            downCount++;
          } else if (record.status === 'warning') {
            warningCount++;
          } else if (record.status === 'up') {
            upCount++;
          }
        });

        // 确定主要状态（优先 down > warning > up）
        let mainStatus = null;
        if (downCount > 0) {
          mainStatus = 'down';
        } else if (warningCount > 0) {
          mainStatus = 'warning';
        } else if (upCount > 0) {
          mainStatus = 'up';
        }

        chartData.push({
          checked_at: segmentEnd.toISOString(),
          response_time: responseTimeCount > 0 ? Math.round(totalResponseTime / responseTimeCount) : null,
          status: mainStatus,
          count: segmentRecords.length,
          min_response_time: minResponseTime,
          max_response_time: maxResponseTime
        });
      } else {
        // 该时间段没有数据
        chartData.push({
          checked_at: segmentEnd.toISOString(),
          response_time: null,
          status: null,
          count: 0
        });
      }
    }

    // 获取历史记录表格数据（最近N条，按时间倒序，仅选择必要字段）
    const [historyRows] = await execQuery(pool!,
      `SELECT id, status, response_time, message, checked_at
       FROM check_history
       WHERE monitor_id = ?
         AND checked_at >= DATE_SUB(NOW(), INTERVAL ${hours} HOUR)
       ORDER BY checked_at DESC
       LIMIT ${historyLimit}`,
      [req.params.id]
    );

    res.json({
      chartData: chartData, // 已经是按时间正序排列（从旧到新，最新在右边）
      history: historyRows,
      stats: {
        total: stats[0].total || 0,
        upCount: stats[0].up_count || 0,
        uptime: stats[0].total > 0 ? ((stats[0].up_count / stats[0].total) * 100).toFixed(2) : 0,
        avgResponse: Math.round(stats[0].avg_response) || 0,
        minResponse: stats[0].min_response || 0,
        maxResponse: stats[0].max_response || 0
      }
    });
  } catch (e) {
    log('ERROR', '获取历史记录失败', {monitorId: req.params.id, range, error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

// ============ 设置 API ============
app.get('/api/settings', authMiddleware, async (req: Request, res: Response) => {
  try {
    if (!pool) {
      return res.json({
        publicPageTitle: '服务状态监控',
        logRetentionDays: 30,
        adminEmail: null,
        logTableSize: null,
        smtpPassword: '',
        smtpPasswordSet: false
      });
    }

    try {
      // 获取公开展示页面标题
      const [titleRows] = await execQuery(pool!,
        'SELECT value FROM settings WHERE key_name = ?',
        ['publicPageTitle']
      );

      const publicPageTitle = titleRows.length > 0 && titleRows[0].value
        ? titleRows[0].value
        : '服务状态监控';

      // 获取日志保留天数
      const [retentionRows] = await execQuery(pool!,
        'SELECT value FROM settings WHERE key_name = ?',
        ['logRetentionDays']
      );

      const logRetentionDays = retentionRows.length > 0 && retentionRows[0].value
        ? parseInt(retentionRows[0].value, 10)
        : 30;

      // 获取当前管理员邮箱
      let adminEmail = null;
      if (req.user && req.user.username) {
        const [userRows] = await execQuery(pool!,
          'SELECT email FROM users WHERE username = ? AND role = ?',
          [req.user.username, 'admin']
        );
        if (userRows.length > 0) {
          adminEmail = userRows[0].email || null;
        }
      }

      // 获取邮件配置
      const [smtpRows] = await execQuery(pool!,
        'SELECT key_name, value FROM settings WHERE key_name IN (?, ?, ?, ?, ?, ?)',
        ['smtpHost', 'smtpPort', 'smtpUser', 'smtpPassword', 'smtpFrom', 'smtpSecure']
      );

      const smtpConfig: Record<string, string> = {};
      smtpRows.forEach((row: SettingsRow) => {
        smtpConfig[row.key_name] = row.value || '';
      });
      const smtpPasswordSet = !!(smtpConfig.smtpPassword && String(smtpConfig.smtpPassword).trim());

      // 获取 Webhook 配置
      const [webhookRows] = await execQuery(pool!,
        'SELECT key_name, value FROM settings WHERE key_name IN (?, ?, ?)',
        ['webhookUrl', 'webhookMethod', 'webhookHeaders']
      );

      const webhookConfig: Record<string, string> = {};
      webhookRows.forEach((row: SettingsRow) => {
        webhookConfig[row.key_name] = row.value || '';
      });

      // 获取日志表大小
      let logTableSize = null;
      try {
        // 获取表大小
        const [sizeRows] = await execQuery(pool!,
          `SELECT ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb
           FROM information_schema.tables
           WHERE table_schema = DATABASE()
             AND table_name = 'check_history'`
        );

        // 获取实际记录数（更准确）
        const [countRows] = await execQuery(pool!,'SELECT COUNT(*) as count FROM check_history');

        if (sizeRows.length > 0 && sizeRows[0].size_mb !== null) {
          logTableSize = {
            sizeMB: parseFloat(sizeRows[0].size_mb) || 0,
            rows: parseInt(countRows[0].count) || 0
          };
        }
      } catch (e) {
        log('WARN', '获取日志表大小失败', {error: e.message});
      }

      res.json({
        publicPageTitle,
        logRetentionDays: isNaN(logRetentionDays) ? 30 : logRetentionDays,
        adminEmail,
        smtpHost: smtpConfig.smtpHost || '',
        smtpPort: smtpConfig.smtpPort || '587',
        smtpUser: smtpConfig.smtpUser || '',
        // 不返回敏感密码，仅返回是否已设置
        smtpPassword: '',
        smtpPasswordSet,
        smtpFrom: smtpConfig.smtpFrom || '',
        smtpSecure: smtpConfig.smtpSecure === '1' || smtpConfig.smtpSecure === 'true',
        webhookUrl: webhookConfig.webhookUrl || '',
        webhookMethod: webhookConfig.webhookMethod || 'POST',
        webhookHeaders: webhookConfig.webhookHeaders || '',
        logTableSize
      });
    } catch (dbError) {
      // 如果表不存在或其他数据库错误，返回默认值
      log('WARN', '获取设置失败，使用默认值', {error: dbError.message, user: req.user?.username});
      res.json({
        publicPageTitle: '服务状态监控',
        logRetentionDays: 30,
        adminEmail: null,
        logTableSize: null,
        smtpPassword: '',
        smtpPasswordSet: false
      });
    }
  } catch (e) {
    log('ERROR', '获取设置失败', {error: e.message, user: req.user?.username});
    res.json({
      publicPageTitle: '服务状态监控',
      logRetentionDays: 30,
      adminEmail: null,
      logTableSize: null,
      smtpPassword: '',
      smtpPasswordSet: false
    });
  }
});

app.post('/api/settings/test-webhook', authMiddleware, async (req: Request, res: Response) => {
  try {
    // 从请求体获取 Webhook 配置（从页面表单获取）
    const {webhookUrl, webhookMethod, webhookHeaders} = req.body;

    // 验证必填项
    if (!webhookUrl) {
      return res.status(400).json({error: 'Webhook URL 不能为空'});
    }

    const method = (webhookMethod || 'POST').toUpperCase();
    let headers = {
      'Content-Type': 'application/json',
      'User-Agent': 'Xilore-Uptime/1.0'
    };

    // 解析请求头
    if (webhookHeaders) {
      try {
        const customHeaders = typeof webhookHeaders === 'string' ? JSON.parse(webhookHeaders) : webhookHeaders;
        headers = {...headers, ...customHeaders};
      } catch (e) {
        return res.status(400).json({error: '请求头格式错误，必须是有效的 JSON'});
      }
    }

    // 构建测试请求体
    const payload = {
      event: 'test',
      message: '这是一条测试 Webhook 消息',
      timestamp: new Date().toISOString(),
      time: new Date().toLocaleString('zh-CN')
    };

    // 发送 Webhook 请求
    const parsedUrl = new URL(webhookUrl);
    const httpModule = parsedUrl.protocol === 'https:' ? require('https') : require('http');

    const requestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: method,
      headers: headers
    };

    await new Promise((resolve: (v?: void) => void, reject: (e: Error) => void) => {
      const req = httpModule.request(requestOptions, (res: http.IncomingMessage) => {
        let data = '';
        res.on('data', (chunk: Buffer | string) => {
          data += chunk;
        });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            log('INFO', '测试 Webhook 发送成功', {statusCode: res.statusCode, user: req.user?.username});
            resolve(undefined);
          } else {
            log('WARN', '测试 Webhook 返回非成功状态码', {
              statusCode: res.statusCode,
              user: req.user?.username
            });
            // 根据状态码返回友好的错误信息
            const code = res.statusCode || 0;
            let errorMsg = `HTTP ${code}`;
            if (code === 404) {
              errorMsg = 'Webhook URL 不存在 (404)';
            } else if (code === 401) {
              errorMsg = '认证失败，请检查请求头配置 (401)';
            } else if (code === 403) {
              errorMsg = '访问被拒绝 (403)';
            } else if (code === 500) {
              errorMsg = '目标服务器内部错误 (500)';
            }
            reject(new Error(errorMsg));
          }
        });
      });

      req.on('error', (err: Error) => {
        log('ERROR', '测试 Webhook 请求失败', {error: err.message, user: req.user?.username});
        reject(err);
      });

      req.setTimeout(10000); // 10秒超时
      req.on('timeout', () => {
        req.destroy();
        log('ERROR', '测试 Webhook 请求超时', {user: req.user?.username});
        reject(new Error('Request timeout'));
      });

      if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        req.write(JSON.stringify(payload));
      }

      req.end();
    });

    res.json({success: true, message: 'Webhook 测试成功'});
  } catch (error) {
    log('ERROR', '测试 Webhook 失败', {error: error.message, user: req.user?.username});
    res.status(500).json({error: '测试失败: ' + error.message});
  }
});

app.post('/api/settings/test-email', authMiddleware, async (req: Request, res: Response) => {
  try {
    // 从请求体获取邮件配置（从页面表单获取）
    const {smtpHost, smtpPort, smtpUser, smtpPassword, smtpFrom, smtpSecure, toEmail} = req.body;

    // 验证必填项
    if (!smtpHost || !smtpUser || !smtpPassword || !smtpFrom || !toEmail) {
      return res.status(400).json({error: '邮件配置不完整'});
    }

    const port = parseInt(smtpPort) || 587;
    const secure = smtpSecure === true || smtpSecure === 'true' || smtpSecure === 1;

    // 创建邮件传输器
    const transporter = (nodemailer as any).createTransport({
      host: smtpHost,
      port: port,
      secure: secure,
      auth: {
        user: smtpUser,
        pass: smtpPassword
      }
    });

    // 发送测试邮件
    const sendTime = new Date().toLocaleString('zh-CN');
    const secureText = secure ? 'SSL/TLS' : 'STARTTLS';
    const testHtml = renderTemplate('test-email.template', {
      SEND_TIME: escapeHtml(sendTime),
      SMTP_HOST: escapeHtml(smtpHost),
      SMTP_PORT: escapeHtml(String(port)),
      SECURE_TEXT: escapeHtml(secureText),
      SMTP_FROM: escapeHtml(smtpFrom),
      YEAR: String(new Date().getFullYear())
    });
    await transporter.sendMail({
      from: smtpFrom,
      to: toEmail,
      subject: '测试邮件 - Xilore Uptime',
      html: testHtml
    });

    log('INFO', '测试邮件发送成功', {to: toEmail, user: req.user?.username});
    res.json({success: true, message: '测试邮件已发送到 ' + toEmail});
  } catch (error) {
    log('ERROR', '测试邮件发送失败', {error: error.message, user: req.user?.username});
    res.status(500).json({error: '发送失败: ' + error.message});
  }
});

app.put('/api/settings', authMiddleware, async (req: Request, res: Response) => {
  try {
    if (!pool) {
      return res.status(500).json({error: '数据库未连接'});
    }

    const {
      publicPageTitle,
      logRetentionDays,
      adminEmail,
      adminPassword,
      adminPasswordConfirm,
      smtpHost,
      smtpPort,
      smtpUser,
      smtpPassword,
      smtpFrom,
      smtpSecure,
      webhookUrl,
      webhookMethod,
      webhookHeaders
    } = req.body;

    if (publicPageTitle !== undefined) {
      const value = publicPageTitle || '服务状态监控';

      // 使用 INSERT ... ON DUPLICATE KEY UPDATE 来插入或更新
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['publicPageTitle', value, value]
      );

      // 刷新服务端标题缓存，确保保存后立刻生效
      cachedPublicTitle = value;
      cachedPublicTitleAt = Date.now();

      log('INFO', '更新设置成功', {publicPageTitle: value, user: req.user?.username});
    }

    if (logRetentionDays !== undefined) {
      const retentionDays = parseInt(logRetentionDays, 10);
      if (isNaN(retentionDays) || retentionDays < 30) {
        return res.status(400).json({error: '日志保留天数必须至少为30天'});
      }

      const value = retentionDays.toString();

      // 使用 INSERT ... ON DUPLICATE KEY UPDATE 来插入或更新
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['logRetentionDays', value, value]
      );

      log('INFO', '更新设置成功', {logRetentionDays: retentionDays, user: req.user?.username});

      // 重新调度定时任务以应用新的设置
      scheduleLogCleanup();
    }

    // 更新管理员邮箱
    if (adminEmail !== undefined && req.user && req.user.username) {
      const email = adminEmail ? adminEmail.trim() : null;
      await execQuery(pool!,
        'UPDATE users SET email = ? WHERE username = ? AND role = ?',
        [email, req.user.username, 'admin']
      );
      log('INFO', '更新管理员邮箱成功', {email, user: req.user.username});
    }

    // 更新管理员密码
    if (adminPassword !== undefined && adminPassword !== null && adminPassword !== '') {
      if (adminPassword.length < 6) {
        return res.status(400).json({error: '密码长度至少6位'});
      }

      if (adminPassword !== adminPasswordConfirm) {
        return res.status(400).json({error: '两次输入的密码不一致'});
      }

      if (req.user && req.user.username) {
        const hashedPassword = await bcrypt.hash(adminPassword, 10);
        await execQuery(pool!,
          'UPDATE users SET password = ? WHERE username = ? AND role = ?',
          [hashedPassword, req.user.username, 'admin']
        );
        log('INFO', '更新管理员密码成功', {user: req.user.username});
      }
    }

    // 更新邮件配置
    if (smtpHost !== undefined) {
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['smtpHost', smtpHost || '', smtpHost || '']
      );
    }

    if (smtpPort !== undefined) {
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['smtpPort', smtpPort || '587', smtpPort || '587']
      );
    }

    if (smtpUser !== undefined) {
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['smtpUser', smtpUser || '', smtpUser || '']
      );
    }

    if (smtpPassword !== undefined) {
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['smtpPassword', smtpPassword || '', smtpPassword || '']
      );
    }

    if (smtpFrom !== undefined) {
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['smtpFrom', smtpFrom || '', smtpFrom || '']
      );
    }

    if (smtpSecure !== undefined) {
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['smtpSecure', smtpSecure ? '1' : '0', smtpSecure ? '1' : '0']
      );
    }

    // 更新 Webhook 配置
    if (webhookUrl !== undefined) {
      const value = webhookUrl || '';
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['webhookUrl', value, value]
      );
    }

    if (webhookMethod !== undefined) {
      const value = (webhookMethod || 'POST').toUpperCase();
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['webhookMethod', value, value]
      );
    }

    if (webhookHeaders !== undefined) {
      const value = typeof webhookHeaders === 'string'
        ? (webhookHeaders || '')
        : JSON.stringify(webhookHeaders || {});
      await execQuery(pool!,
        `INSERT INTO settings (key_name, value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value      = ?,
                                 updated_at = CURRENT_TIMESTAMP`,
        ['webhookHeaders', value, value]
      );
    }

    // 返回更新后的设置
    const [titleRows] = await execQuery(pool!,
      'SELECT value FROM settings WHERE key_name = ?',
      ['publicPageTitle']
    );

    const updatedTitle = titleRows.length > 0 && titleRows[0].value
      ? titleRows[0].value
      : '服务状态监控';

    const [retentionRows] = await execQuery(pool!,
      'SELECT value FROM settings WHERE key_name = ?',
      ['logRetentionDays']
    );

    const updatedRetention = retentionRows.length > 0 && retentionRows[0].value
      ? parseInt(retentionRows[0].value, 10)
      : 30;

    // 获取更新后的管理员邮箱
    let updatedEmail = null;
    if (req.user && req.user.username) {
      const [userRows] = await execQuery(pool!,
        'SELECT email FROM users WHERE username = ? AND role = ?',
        [req.user.username, 'admin']
      );
      if (userRows.length > 0) {
        updatedEmail = userRows[0].email || null;
      }
    }

    // 获取更新后的邮件配置
    const [updatedSmtpRows] = await execQuery(pool!,
      'SELECT key_name, value FROM settings WHERE key_name IN (?, ?, ?, ?, ?, ?)',
      ['smtpHost', 'smtpPort', 'smtpUser', 'smtpPassword', 'smtpFrom', 'smtpSecure']
    );

    const updatedSmtpConfig: Record<string, string> = {};
    updatedSmtpRows.forEach((row: SettingsRow) => {
      updatedSmtpConfig[row.key_name] = row.value || '';
    });
    const smtpPasswordSet = !!(updatedSmtpConfig.smtpPassword && String(updatedSmtpConfig.smtpPassword).trim());

    // 获取更新后的 Webhook 配置
    const [updatedWebhookRows] = await execQuery(pool!,
      'SELECT key_name, value FROM settings WHERE key_name IN (?, ?, ?)',
      ['webhookUrl', 'webhookMethod', 'webhookHeaders']
    );

    const updatedWebhookConfig: Record<string, string> = {};
    updatedWebhookRows.forEach((row: SettingsRow) => {
      updatedWebhookConfig[row.key_name] = row.value || '';
    });

    res.json({
      publicPageTitle: updatedTitle,
      logRetentionDays: isNaN(updatedRetention) ? 30 : updatedRetention,
      adminEmail: updatedEmail,
      smtpHost: updatedSmtpConfig.smtpHost || '',
      smtpPort: updatedSmtpConfig.smtpPort || '587',
      smtpUser: updatedSmtpConfig.smtpUser || '',
      // 不返回敏感密码，仅返回是否已设置
      smtpPassword: '',
      smtpPasswordSet,
      smtpFrom: updatedSmtpConfig.smtpFrom || '',
      smtpSecure: updatedSmtpConfig.smtpSecure === '1' || updatedSmtpConfig.smtpSecure === 'true',
      webhookUrl: updatedWebhookConfig.webhookUrl || '',
      webhookMethod: updatedWebhookConfig.webhookMethod || 'POST',
      webhookHeaders: updatedWebhookConfig.webhookHeaders || ''
    });
  } catch (e) {
    log('ERROR', '更新设置失败', {error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

// ============ 日志清理功能 ============
async function cleanupOldLogs() {
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
      log('WARN', '日志保留天数设置无效，使用默认值30天');
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
      log('INFO', '日志清理完成', {
        retentionDays,
        deletedRecords: result.affectedRows,
        cutoffDate: cutoffDate.toISOString()
      });
    } else {
      log('INFO', '日志清理完成，无需删除记录', {retentionDays});
    }
  } catch (e) {
    log('ERROR', '日志清理失败', {error: e.message});
  }
}

// ============ 定时任务：每天00:00执行日志清理 ============
function scheduleLogCleanup() {
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

  log('INFO', '定时任务已设置', {
    nextCleanup: nextMidnight.toISOString(),
    msUntilMidnight
  });

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
  try {
    // 统计信息合并为一次查询（减少 DB 往返）
    const [statsRows] = await execQuery(pool!,
      `SELECT COUNT(*)                                                                           AS total,
              SUM(IF(enabled = 0, 1, 0))                                                         AS paused,
              SUM(IF(enabled = 1 AND (status = 'up' OR status = 'warning'), 1, 0))               AS up,
              SUM(IF(enabled = 1 AND (status IS NULL OR status NOT IN ('up', 'warning')), 1, 0)) AS down
       FROM monitors`
    );
    const base = statsRows[0] || {total: 0, paused: 0, up: 0, down: 0};

    // 计算24小时平均可用率（warning也算作可用）- 聚合在 DB 内完成
    const [uptimeAvgRows] = await execQuery(pool!,
      `SELECT AVG(t.uptime) AS avg_uptime
       FROM (SELECT (SUM(IF(h.status IN ('up', 'warning'), 1, 0)) / COUNT(h.id)) * 100 AS uptime
             FROM monitors m
                      JOIN check_history h ON m.id = h.monitor_id
                 AND h.checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
             WHERE m.enabled = 1
             GROUP BY m.id) t`
    );
    const avgUptimeRaw = uptimeAvgRows[0]?.avg_uptime;
    const avgUptime = avgUptimeRaw === null || avgUptimeRaw === undefined ? 100 : Number(avgUptimeRaw);

    res.json({
      total: Number(base.total) || 0,
      up: Number(base.up) || 0,
      down: Number(base.down) || 0,
      paused: Number(base.paused) || 0,
      avgUptime24h: avgUptime
    });
  } catch (e) {
    log('ERROR', 'API 错误', {path: req.path, method: req.method, error: e.message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

app.post('/api/check-all', authMiddleware, async (req: Request, res: Response) => {
  try {
    log('INFO', '开始批量检测所有监控', {user: req.user?.username});
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

    log('INFO', '批量检测完成', {total: monitors.length, user: req.user?.username});
    res.json(results);
  } catch (e: unknown) {
    log('ERROR', '批量检测失败', {error: (e as Error).message, user: req.user?.username});
    res.status(500).json({error: (e as Error).message});
  }
});

// ============ 定时检测任务 ============
const checkIntervals = new Map();

function startMonitorCheck(monitor: MonitorRow): void {
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
        log('INFO', '监控任务已停止', {monitorId: monitor.id, reason: rows.length === 0 ? '已删除' : '已禁用'});
      }
    } catch (e) {
      log('ERROR', '定时检测失败', {monitorId: monitor.id, error: e.message});
    }
  }, monitor.interval_seconds * 1000);

  checkIntervals.set(monitor.id, interval);
}

async function initializeChecks() {
  if (!pool) return;

  try {
    const [monitors] = await execQuery(pool!,'SELECT * FROM monitors WHERE enabled = 1');
    monitors.forEach(startMonitorCheck);
    log('INFO', '初始化监控任务', {count: monitors.length});
  } catch (e) {
    log('ERROR', '初始化监控任务失败', {error: e.message});
  }
}

setInterval(async () => {
  if (!pool) return;

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

// ============ 公开 API（不需要认证）============
app.get('/api/public/title', async (req: Request, res: Response) => {
  try {
    if (!pool) {
      return res.json({title: '服务状态监控'});
    }

    try {
      const [rows] = await execQuery(pool!,
        'SELECT value FROM settings WHERE key_name = ?',
        ['publicPageTitle']
      );

      const title = rows.length > 0 && rows[0].value
        ? rows[0].value
        : '服务状态监控';

      res.json({title});
    } catch (dbError) {
      // 如果表不存在或其他数据库错误，返回默认值
      log('WARN', '获取公开页面标题失败，使用默认值', {error: dbError.message});
      res.json({title: '服务状态监控'});
    }
  } catch (e: unknown) {
    log('ERROR', '公开API错误', {path: req.path, method: req.method, error: (e as Error).message});
    res.status(500).json({error: (e as Error).message});
  }
});

app.get('/api/public/groups', async (req: Request, res: Response) => {
  try {
    // 获取所有分组，但只返回那些有公开服务的分组
    const [rows] = await execQuery(pool!,
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
    log('ERROR', '公开API错误', {path: req.path, method: req.method, error: (e as Error).message});
    res.status(500).json({error: (e as Error).message});
  }
});

app.get('/api/public/monitors', async (req: Request, res: Response) => {
  try {
    // 只返回公开展示需要的字段，不暴露 type、target、port 等敏感信息
    const [rows] = await execQuery(pool!,
      'SELECT id, name, status, group_id, enabled, last_response_time, last_check FROM monitors WHERE is_public = 1 ORDER BY group_id, created_at DESC'
    );

    const ids = rows.map((m: MonitorRow) => m.id);
    const uptimeMap = new Map();
    if (ids.length > 0) {
      const inPlaceholders = ids.map(() => '?').join(',');
      const [uptimeRows] = await execQuery(pool!,
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
    log('ERROR', '公开API错误', {path: req.path, method: req.method, error: (e as Error).message});
    res.status(500).json({error: (e as Error).message});
  }
});

// 批量获取监控状态条数据（用于异步加载）
app.get('/api/public/monitors/statusbars', async (req: Request, res: Response) => {
  try {
    const [rows] = await execQuery(pool!,"SELECT id FROM monitors WHERE is_public = 1");
    const ids = rows.map((r: MonitorRow) => Number(r.id)).filter((v: number) => Number.isFinite(v));
    if (ids.length === 0) {
      return res.json([]);
    }

    const inPlaceholders = ids.map(() => '?').join(',');
    const [historyRows] = await execQuery(pool!,
      `SELECT monitor_id, status, checked_at, message
       FROM check_history
       WHERE checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         AND monitor_id IN (${inPlaceholders})
       ORDER BY monitor_id, checked_at`,
      ids
    );

    res.json(buildStatusBars24h(ids, historyRows));
  } catch (e: unknown) {
    log('ERROR', '公开API错误', {path: req.path, method: req.method, error: (e as Error).message});
    res.status(500).json({error: (e as Error).message});
  }
});

app.get('/api/public/stats', async (req: Request, res: Response) => {
  try {
    // 获取基础统计
    const [rows] = await execQuery(pool!,
      `SELECT COUNT(*)                          as total,
              SUM(IF(status = 'up', 1, 0))      as up,
              SUM(IF(status = 'down', 1, 0))    as down,
              SUM(IF(status = 'unknown', 1, 0)) as unknown
       FROM monitors
       WHERE is_public = 1
         AND enabled = 1`
    );

    const stats = rows[0] || {total: 0, up: 0, down: 0, unknown: 0};

    // 计算24小时可用率（warning也算作可用）
    const [uptimeRows] = await execQuery(pool!,
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
    log('ERROR', '公开API错误', {path: req.path, method: req.method, error: (e as Error).message});
    res.status(500).json({error: (e as Error).message});
  }
});

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
    log('WARN', '检查初始化状态失败', {error: error.message});
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
    log('ERROR', '渲染首页失败', {error: e.message});
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
    log('ERROR', '渲染管理页失败', {error: e.message});
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
    log('ERROR', '渲染 404 页面失败', {error: (e as Error).message, path: req.path});
    res.status(404).send('404 Not Found');
  }
});

// ============ 启动服务器 ============
async function start(): Promise<void> {
  loadConfig();

  if (isInstalled()) {
    try {
      await connectDatabaseWrapper();
      await initializeTables(pool);
      await initializeChecks();
      // 启动日志清理定时任务
      scheduleLogCleanup();
      log('INFO', '服务器启动成功', {port: PORT});
    } catch (e: unknown) {
      log('ERROR', '连接数据库失败', {error: (e as Error).message});
      log('WARN', '请检查数据库配置或删除 config.json 重新安装');
    }
  } else {
    log('INFO', '系统未安装，等待初始化设置');
  }

  app.listen(PORT, () => {
    log('INFO', 'HTTP 服务器启动', {port: PORT});
    console.log(`
╔═══════════════════════════════════════════════╗
║                                               ║
║   Xilore UptimeBot 监控服务已启动             ║
║                                               ║
║   访问地址: http://localhost:${PORT}             ║
║                                               ║
╚═══════════════════════════════════════════════╝
    `);
  });
}

start().catch((error: Error) => {
  log('ERROR', '服务器启动失败', {error: error.message, stack: error.stack});
  process.exit(1);
});
