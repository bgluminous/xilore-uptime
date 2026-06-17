import type { Express, Request, RequestHandler, Response } from 'express';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import type { Pool } from 'mysql2/promise';
import type { SettingsRow } from '../core/db-types.js';
import { execQuery } from '../core/db-utils.js';
import { sendFeishuRequest } from '../features/notifications.js';
import { escapeHtml, renderTemplate } from '../core/templates.js';

interface RouteLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

interface SettingsRoutesContext {
  getPool(): Pool | null;
  logger: RouteLogger;
  authMiddleware: RequestHandler;
  setPublicPageTitleCache(title: string): void;
  scheduleLogCleanup(): void;
}

interface SettingsPayload {
  publicPageTitle: string;
  logRetentionDays: number;
  adminEmail: string | null;
  smtpHost: string;
  smtpPort: string;
  smtpUser: string;
  smtpPassword: string;
  smtpPasswordSet: boolean;
  smtpFrom: string;
  smtpSecure: boolean;
  webhookUrl: string;
  webhookMethod: string;
  webhookHeaders: string;
  feishuWebhookUrl: string;
  feishuSecret: string;
  feishuSecretSet: boolean;
  logTableSize?: { sizeMB: number; rows: number } | null;
}

const DEFAULT_SETTINGS = {
  publicPageTitle: '服务状态监控',
  logRetentionDays: 30,
  adminEmail: null,
  logTableSize: null,
  smtpPassword: '',
  smtpPasswordSet: false,
  feishuWebhookUrl: '',
  feishuSecret: '',
  feishuSecretSet: false
};

export function registerSettingsRoutes(app: Express, ctx: SettingsRoutesContext): void {
  const {authMiddleware, logger} = ctx;

  app.get('/api/settings', authMiddleware, async (req: Request, res: Response) => {
    try {
      const pool = ctx.getPool();
      if (!pool) {
        return res.json(DEFAULT_SETTINGS);
      }

      try {
        res.json(await loadSettingsPayload(pool, req.user?.username, logger, true));
      } catch (dbError) {
        logger.warn(`获取设置失败，使用默认值 ${JSON.stringify({error: dbError.message, user: req.user?.username})}`);
        res.json(DEFAULT_SETTINGS);
      }
    } catch (e) {
      logger.error(`获取设置失败 ${JSON.stringify({error: e.message, user: req.user?.username})}`);
      res.json(DEFAULT_SETTINGS);
    }
  });

  app.post('/api/settings/test-webhook', authMiddleware, async (req: Request, res: Response) => {
    try {
      const {webhookUrl, webhookMethod, webhookHeaders} = req.body;

      if (!webhookUrl) {
        return res.status(400).json({error: 'Webhook URL 不能为空'});
      }

      const method = (webhookMethod || 'POST').toUpperCase();
      let headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Xilore-Uptime/1.0'
      };

      if (webhookHeaders) {
        try {
          const customHeaders = typeof webhookHeaders === 'string' ? JSON.parse(webhookHeaders) : webhookHeaders;
          headers = {...headers, ...customHeaders};
        } catch (e) {
          return res.status(400).json({error: '请求头格式错误，必须是有效的 JSON'});
        }
      }

      const payload = {
        event: 'test',
        message: '这是一条测试 Webhook 消息',
        timestamp: new Date().toISOString(),
        time: new Date().toLocaleString('zh-CN')
      };

      const parsedUrl = new URL(webhookUrl);
      const httpModule = parsedUrl.protocol === 'https:' ? https : http;

      const requestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: method,
        headers: headers
      };

      const currentUser = req.user?.username;
      await new Promise((resolve: (v?: void) => void, reject: (e: Error) => void) => {
        const httpReq = httpModule.request(requestOptions, (response: http.IncomingMessage) => {
          let data = '';
          response.on('data', (chunk: Buffer | string) => {
            data += chunk;
          });
          response.on('end', () => {
            if (response.statusCode && response.statusCode >= 200 && response.statusCode < 300) {
              logger.info(`测试 Webhook 发送成功 ${JSON.stringify({statusCode: response.statusCode, user: currentUser})}`);
              resolve(undefined);
            } else {
              logger.warn(`测试 Webhook 返回非成功状态码 ${JSON.stringify({
                statusCode: response.statusCode,
                user: currentUser
              })}`);
              const code = response.statusCode || 0;
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

        httpReq.on('error', (err: Error) => {
          logger.error(`测试 Webhook 请求失败 ${JSON.stringify({error: err.message, user: currentUser})}`);
          reject(err);
        });

        httpReq.setTimeout(10000);
        httpReq.on('timeout', () => {
          httpReq.destroy();
          logger.error(`测试 Webhook 请求超时 ${JSON.stringify({user: currentUser})}`);
          reject(new Error('Request timeout'));
        });

        if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
          httpReq.write(JSON.stringify(payload));
        }

        httpReq.end();
      });

      res.json({success: true, message: 'Webhook 测试成功'});
    } catch (error) {
      logger.error(`测试 Webhook 失败 ${JSON.stringify({error: error.message, user: req.user?.username})}`);
      res.status(500).json({error: '测试失败: ' + error.message});
    }
  });

  app.post('/api/settings/test-feishu', authMiddleware, async (req: Request, res: Response) => {
    try {
      const pool = ctx.getPool();
      const {feishuWebhookUrl, feishuSecret} = req.body;

      if (!feishuWebhookUrl) {
        return res.status(400).json({error: '飞书 Webhook URL 不能为空'});
      }

      let secret = feishuSecret;
      if (!Object.prototype.hasOwnProperty.call(req.body, 'feishuSecret')) {
        const [rows] = await execQuery(pool!,
          'SELECT value FROM settings WHERE key_name = ?',
          ['feishuSecret']
        );
        secret = rows.length > 0 ? rows[0].value || '' : '';
      }

      const sendTime = new Date().toLocaleString('zh-CN');
      const card = {
        config: {
          wide_screen_mode: true
        },
        header: {
          template: 'blue',
          title: {
            tag: 'plain_text',
            content: 'Xilore Uptime 飞书测试'
          }
        },
        elements: [
          {
            tag: 'div',
            text: {
              tag: 'lark_md',
              content: [
                '**消息类型：** 测试通知',
                '**发送结果：** 如果您收到这条消息，说明飞书配置可用。',
                `**发送时间：** ${sendTime}`
              ].join('\n')
            }
          }
        ]
      };

      const result = await sendFeishuRequest(feishuWebhookUrl, secret, card, {user: req.user?.username, test: true}, logger);
      if (result.statusCode < 200 || result.statusCode >= 300) {
        logger.warn(`测试飞书返回非成功状态码 ${JSON.stringify({statusCode: result.statusCode, user: req.user?.username})}`);
        return res.status(500).json({error: `测试失败: HTTP ${result.statusCode}`});
      }

      if (result.data && typeof result.data.code === 'number' && result.data.code !== 0) {
        const msg = result.data.msg || result.data.message || '飞书返回失败';
        logger.warn(`测试飞书返回失败 ${JSON.stringify({code: result.data.code, msg, user: req.user?.username})}`);
        return res.status(500).json({error: `测试失败: ${msg}`});
      }

      logger.info(`测试飞书发送成功 ${JSON.stringify({statusCode: result.statusCode, user: req.user?.username})}`);
      res.json({success: true, message: '飞书测试消息发送成功'});
    } catch (error) {
      logger.error(`测试飞书失败 ${JSON.stringify({error: error.message, user: req.user?.username})}`);
      res.status(500).json({error: '测试失败: ' + error.message});
    }
  });

  app.post('/api/settings/test-email', authMiddleware, async (req: Request, res: Response) => {
    try {
      const {smtpHost, smtpPort, smtpUser, smtpPassword, smtpFrom, smtpSecure, toEmail} = req.body;

      if (!smtpHost || !smtpUser || !smtpPassword || !smtpFrom || !toEmail) {
        return res.status(400).json({error: '邮件配置不完整'});
      }

      const port = parseInt(smtpPort) || 587;
      const secure = smtpSecure === true || smtpSecure === 'true' || smtpSecure === 1;

      const transporter = (nodemailer as any).createTransport({
        host: smtpHost,
        port: port,
        secure: secure,
        auth: {
          user: smtpUser,
          pass: smtpPassword
        }
      });

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

      logger.info(`测试邮件发送成功 ${JSON.stringify({to: toEmail, user: req.user?.username})}`);
      res.json({success: true, message: '测试邮件已发送到 ' + toEmail});
    } catch (error) {
      logger.error(`测试邮件发送失败 ${JSON.stringify({error: error.message, user: req.user?.username})}`);
      res.status(500).json({error: '发送失败: ' + error.message});
    }
  });

  app.put('/api/settings', authMiddleware, async (req: Request, res: Response) => {
    try {
      const pool = ctx.getPool();
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
        webhookHeaders,
        feishuWebhookUrl,
        feishuSecret
      } = req.body;

      if (publicPageTitle !== undefined) {
        const value = publicPageTitle || '服务状态监控';

        await execQuery(pool,
          `INSERT INTO settings (key_name, value)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE value      = ?,
                                   updated_at = CURRENT_TIMESTAMP`,
          ['publicPageTitle', value, value]
        );

        ctx.setPublicPageTitleCache(value);
        logger.info(`更新设置成功 ${JSON.stringify({publicPageTitle: value, user: req.user?.username})}`);
      }

      if (logRetentionDays !== undefined) {
        const retentionDays = parseInt(logRetentionDays, 10);
        if (isNaN(retentionDays) || retentionDays < 30) {
          return res.status(400).json({error: '日志保留天数必须至少为30天'});
        }

        const value = retentionDays.toString();

        await execQuery(pool,
          `INSERT INTO settings (key_name, value)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE value      = ?,
                                   updated_at = CURRENT_TIMESTAMP`,
          ['logRetentionDays', value, value]
        );

        logger.info(`更新设置成功 ${JSON.stringify({logRetentionDays: retentionDays, user: req.user?.username})}`);
        ctx.scheduleLogCleanup();
      }

      if (adminEmail !== undefined && req.user && req.user.username) {
        const email = adminEmail ? adminEmail.trim() : null;
        await execQuery(pool,
          'UPDATE users SET email = ? WHERE username = ? AND role = ?',
          [email, req.user.username, 'admin']
        );
        logger.info(`更新管理员邮箱成功 ${JSON.stringify({email, user: req.user.username})}`);
      }

      if (adminPassword !== undefined && adminPassword !== null && adminPassword !== '') {
        if (adminPassword.length < 6) {
          return res.status(400).json({error: '密码长度至少6位'});
        }

        if (adminPassword !== adminPasswordConfirm) {
          return res.status(400).json({error: '两次输入的密码不一致'});
        }

        if (req.user && req.user.username) {
          const hashedPassword = await bcrypt.hash(adminPassword, 10);
          await execQuery(pool,
            'UPDATE users SET password = ? WHERE username = ? AND role = ?',
            [hashedPassword, req.user.username, 'admin']
          );
          logger.info(`更新管理员密码成功 ${JSON.stringify({user: req.user.username})}`);
        }
      }

      if (smtpHost !== undefined) {
        await upsertSetting(pool, 'smtpHost', smtpHost || '');
      }

      if (smtpPort !== undefined) {
        await upsertSetting(pool, 'smtpPort', smtpPort || '587');
      }

      if (smtpUser !== undefined) {
        await upsertSetting(pool, 'smtpUser', smtpUser || '');
      }

      if (smtpPassword !== undefined) {
        await upsertSetting(pool, 'smtpPassword', smtpPassword || '');
      }

      if (smtpFrom !== undefined) {
        await upsertSetting(pool, 'smtpFrom', smtpFrom || '');
      }

      if (smtpSecure !== undefined) {
        await upsertSetting(pool, 'smtpSecure', smtpSecure ? '1' : '0');
      }

      if (webhookUrl !== undefined) {
        await upsertSetting(pool, 'webhookUrl', webhookUrl || '');
      }

      if (webhookMethod !== undefined) {
        await upsertSetting(pool, 'webhookMethod', (webhookMethod || 'POST').toUpperCase());
      }

      if (webhookHeaders !== undefined) {
        const value = typeof webhookHeaders === 'string'
          ? (webhookHeaders || '')
          : JSON.stringify(webhookHeaders || {});
        await upsertSetting(pool, 'webhookHeaders', value);
      }

      if (feishuWebhookUrl !== undefined) {
        await upsertSetting(pool, 'feishuWebhookUrl', feishuWebhookUrl || '');
      }

      if (feishuSecret !== undefined) {
        await upsertSetting(pool, 'feishuSecret', feishuSecret || '');
      }

      res.json(await loadSettingsPayload(pool, req.user?.username, logger, false));
    } catch (e) {
      logger.error(`更新设置失败 ${JSON.stringify({error: e.message, user: req.user?.username})}`);
      res.status(500).json({error: (e as Error).message});
    }
  });
}

async function loadSettingsPayload(
  pool: Pool,
  username: string | undefined,
  logger: RouteLogger,
  includeLogTableSize: boolean
): Promise<SettingsPayload> {
  const [titleRows] = await execQuery(pool,
    'SELECT value FROM settings WHERE key_name = ?',
    ['publicPageTitle']
  );

  const publicPageTitle = titleRows.length > 0 && titleRows[0].value
    ? titleRows[0].value
    : '服务状态监控';

  const [retentionRows] = await execQuery(pool,
    'SELECT value FROM settings WHERE key_name = ?',
    ['logRetentionDays']
  );

  const logRetentionDays = retentionRows.length > 0 && retentionRows[0].value
    ? parseInt(retentionRows[0].value, 10)
    : 30;

  let adminEmail = null;
  if (username) {
    const [userRows] = await execQuery(pool,
      'SELECT email FROM users WHERE username = ? AND role = ?',
      [username, 'admin']
    );
    if (userRows.length > 0) {
      adminEmail = userRows[0].email || null;
    }
  }

  const smtpConfig = await loadSettingsMap(pool, ['smtpHost', 'smtpPort', 'smtpUser', 'smtpPassword', 'smtpFrom', 'smtpSecure']);
  const webhookConfig = await loadSettingsMap(pool, ['webhookUrl', 'webhookMethod', 'webhookHeaders']);
  const feishuConfig = await loadSettingsMap(pool, ['feishuWebhookUrl', 'feishuSecret']);

  const payload: SettingsPayload = {
    publicPageTitle,
    logRetentionDays: isNaN(logRetentionDays) ? 30 : logRetentionDays,
    adminEmail,
    smtpHost: smtpConfig.smtpHost || '',
    smtpPort: smtpConfig.smtpPort || '587',
    smtpUser: smtpConfig.smtpUser || '',
    smtpPassword: '',
    smtpPasswordSet: Boolean(smtpConfig.smtpPassword && String(smtpConfig.smtpPassword).trim()),
    smtpFrom: smtpConfig.smtpFrom || '',
    smtpSecure: smtpConfig.smtpSecure === '1' || smtpConfig.smtpSecure === 'true',
    webhookUrl: webhookConfig.webhookUrl || '',
    webhookMethod: webhookConfig.webhookMethod || 'POST',
    webhookHeaders: webhookConfig.webhookHeaders || '',
    feishuWebhookUrl: feishuConfig.feishuWebhookUrl || '',
    feishuSecret: '',
    feishuSecretSet: Boolean(feishuConfig.feishuSecret && String(feishuConfig.feishuSecret).trim())
  };

  if (includeLogTableSize) {
    payload.logTableSize = await loadLogTableSize(pool, logger);
  }

  return payload;
}

async function loadSettingsMap(pool: Pool, keys: string[]): Promise<Record<string, string>> {
  const placeholders = keys.map(() => '?').join(', ');
  const [rows] = await execQuery(pool,
    `SELECT key_name, value FROM settings WHERE key_name IN (${placeholders})`,
    keys
  );

  const config: Record<string, string> = {};
  rows.forEach((row: SettingsRow) => {
    config[row.key_name] = row.value || '';
  });
  return config;
}

async function loadLogTableSize(pool: Pool, logger: RouteLogger): Promise<{ sizeMB: number; rows: number } | null> {
  try {
    const [sizeRows] = await execQuery(pool,
      `SELECT ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb
       FROM information_schema.tables
       WHERE table_schema = DATABASE()
         AND table_name = 'check_history'`
    );

    const [countRows] = await execQuery(pool, 'SELECT COUNT(*) as count FROM check_history');

    if (sizeRows.length > 0 && sizeRows[0].size_mb !== null) {
      return {
        sizeMB: parseFloat(sizeRows[0].size_mb) || 0,
        rows: parseInt(countRows[0].count) || 0
      };
    }
  } catch (e) {
    logger.warn(`获取日志表大小失败 ${JSON.stringify({error: e.message})}`);
  }

  return null;
}

async function upsertSetting(pool: Pool, key: string, value: string): Promise<void> {
  await execQuery(pool,
    `INSERT INTO settings (key_name, value)
     VALUES (?, ?)
     ON DUPLICATE KEY UPDATE value      = ?,
                             updated_at = CURRENT_TIMESTAMP`,
    [key, value, value]
  );
}
