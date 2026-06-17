import http from 'http';
import https from 'https';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { URL } from 'url';
import type { Pool } from 'mysql2/promise';
import type { MonitorRow, SettingsRow } from '../core/db-types.js';
import { execQuery } from '../core/db-utils.js';
import { escapeHtml, renderTemplate } from '../core/templates.js';

export type MonitorNotificationType = 'status' | 'create' | 'delete';
type MonitorNotificationChannel = 'email' | 'webhook' | 'feishu';

export interface MonitorNotificationEvent {
  type: MonitorNotificationType;
  monitor: MonitorRow;
  oldStatus?: string | null;
  newStatus?: string | null;
  message?: string;
  responseTime?: number | null;
  timestamp?: Date;
}

interface NotificationLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

export interface NotificationContext {
  pool: Pool;
  logger: NotificationLogger;
}

function isMonitorNotificationEnabled(monitor: MonitorRow, channel: MonitorNotificationChannel): boolean {
  if (channel === 'email') return !!monitor.email_notification;
  if (channel === 'webhook') return !!monitor.webhook_notification;
  return !!monitor.feishu_notification;
}

function shouldDispatchMonitorNotification(event: MonitorNotificationEvent): boolean {
  if (event.type === 'create' || event.type === 'delete') return true;
  if (event.newStatus === 'warning') return true;
  return (event.oldStatus || 'unknown') !== (event.newStatus || 'unknown');
}

function getTargetAddress(monitor: MonitorRow): string {
  return monitor.target + (monitor.port ? ':' + monitor.port : '');
}

function getStatusText(status: string): string {
  if (status === 'up') return '在线';
  if (status === 'down') return '离线';
  if (status === 'warning') return '警告';
  return '未知';
}

function getNotificationActionText(event: MonitorNotificationEvent): string {
  if (event.type === 'create') return '已创建';
  if (event.type === 'delete') return '已删除';
  return getStatusText(event.newStatus || 'unknown');
}

function getNotificationMessage(event: MonitorNotificationEvent): string {
  if (event.message) return event.message;
  if (event.type === 'create') return '监控已创建';
  if (event.type === 'delete') return '监控已删除';
  return '无';
}

function getNotificationEventName(event: MonitorNotificationEvent): string {
  if (event.type === 'create') return 'monitor_created';
  if (event.type === 'delete') return 'monitor_deleted';
  return 'monitor_status_changed';
}

function getNotificationMeta(event: MonitorNotificationEvent): {
  subjectPrefix: string;
  statusText: string;
  statusColor: string;
  statusBgColor: string;
  statusIcon: string;
  template: string;
} {
  if (event.type === 'create') {
    return {
      subjectPrefix: '🆕',
      statusText: '已创建',
      statusColor: '#2563eb',
      statusBgColor: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
      statusIcon: '+',
      template: 'blue'
    };
  }

  if (event.type === 'delete') {
    return {
      subjectPrefix: '🗑️',
      statusText: '已删除',
      statusColor: '#64748b',
      statusBgColor: 'linear-gradient(135deg, #64748b 0%, #475569 100%)',
      statusIcon: '-',
      template: 'grey'
    };
  }

  if (event.newStatus === 'up') {
    return {
      subjectPrefix: '✅',
      statusText: '已恢复',
      statusColor: '#10b981',
      statusBgColor: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
      statusIcon: '✓',
      template: 'green'
    };
  }

  if (event.newStatus === 'warning') {
    return {
      subjectPrefix: '⚠️',
      statusText: '警告',
      statusColor: '#f59e0b',
      statusBgColor: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
      statusIcon: '!',
      template: 'orange'
    };
  }

  return {
    subjectPrefix: '❌',
    statusText: '已离线',
    statusColor: '#ef4444',
    statusBgColor: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
    statusIcon: '✕',
    template: 'red'
  };
}

function getNotificationResponseTimeText(event: MonitorNotificationEvent): string {
  if (event.type !== 'status') return '未检测';
  return (event.responseTime !== null && event.responseTime !== undefined) ? `${event.responseTime}ms` : '超时';
}

export function dispatchMonitorNotification(ctx: NotificationContext, event: MonitorNotificationEvent): void {
  if (!shouldDispatchMonitorNotification(event)) return;

  const senders: Array<{
    channel: MonitorNotificationChannel;
    send: (ctx: NotificationContext, event: MonitorNotificationEvent) => Promise<void>;
  }> = [
    {channel: 'email', send: sendEmailNotification},
    {channel: 'webhook', send: sendWebhookNotification},
    {channel: 'feishu', send: sendFeishuNotification}
  ];

  senders.forEach(({channel, send}) => {
    if (!isMonitorNotificationEnabled(event.monitor, channel)) return;
    send(ctx, event).catch((err: Error) => {
      ctx.logger.error(`发送监控通知失败 ${JSON.stringify({
        monitorId: event.monitor.id,
        channel,
        type: event.type,
        error: err.message
      })}`);
    });
  });
}

async function sendEmailNotification(ctx: NotificationContext, event: MonitorNotificationEvent): Promise<void> {
  const monitor = event.monitor;
  try {
    const [smtpRows] = await execQuery(ctx.pool, 'SELECT key_name, value FROM settings WHERE key_name IN (?, ?, ?, ?, ?, ?)',
      ['smtpHost', 'smtpPort', 'smtpUser', 'smtpPassword', 'smtpFrom', 'smtpSecure']);

    if (smtpRows.length === 0 || !smtpRows.find((r: SettingsRow) => r.key_name === 'smtpHost' && r.value)) {
      ctx.logger.warn(`邮件配置未设置，跳过发送 ${JSON.stringify({monitorId: monitor.id})}`);
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
      ctx.logger.warn(`邮件配置不完整，跳过发送 ${JSON.stringify({monitorId: monitor.id})}`);
      return;
    }

    const [userRows] = await execQuery(ctx.pool, 'SELECT email FROM users WHERE role = ? LIMIT 1', ['admin']);
    if (userRows.length === 0 || !userRows[0].email) {
      ctx.logger.warn(`管理员邮箱未设置，跳过发送 ${JSON.stringify({monitorId: monitor.id})}`);
      return;
    }

    const transporter = (nodemailer as any).createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure || false,
      auth: {
        user: config.user,
        pass: config.password
      }
    });

    const meta = getNotificationMeta(event);
    const oldStatusText = event.type === 'create' ? '无' : getStatusText(event.oldStatus || String(monitor.status || 'unknown'));
    const newStatusText = event.type === 'status' ? getStatusText(event.newStatus || 'unknown') : getNotificationActionText(event);
    const checkTime = (event.timestamp || new Date()).toLocaleString('zh-CN');
    const subject = `${meta.subjectPrefix} 监控通知: ${monitor.name} ${meta.statusText}`;

    const html = renderTemplate('monitor-status-email.template', {
      MONITOR_NAME: escapeHtml(monitor.name),
      STATUS_BG_COLOR: meta.statusBgColor,
      STATUS_COLOR: meta.statusColor,
      STATUS_ICON: escapeHtml(meta.statusIcon),
      STATUS_TEXT: escapeHtml(meta.statusText),
      TARGET_ADDRESS: escapeHtml(getTargetAddress(monitor)),
      TYPE_TEXT: escapeHtml(monitor.type.toUpperCase()),
      OLD_STATUS_TEXT: escapeHtml(oldStatusText),
      NEW_STATUS_TEXT: escapeHtml(newStatusText),
      RESPONSE_TIME_TEXT: escapeHtml(getNotificationResponseTimeText(event)),
      DETAIL_MESSAGE: escapeHtml(getNotificationMessage(event)),
      CHECK_TIME: escapeHtml(checkTime),
      YEAR: String(new Date().getFullYear())
    });

    await transporter.sendMail({
      from: config.from,
      to: userRows[0].email,
      subject,
      html
    });

    ctx.logger.info(`邮件通知发送成功 ${JSON.stringify({monitorId: monitor.id, to: userRows[0].email})}`);
  } catch (error) {
    ctx.logger.error(`发送邮件通知失败 ${JSON.stringify({monitorId: monitor.id, error: error.message})}`);
    throw error;
  }
}

async function sendWebhookNotification(ctx: NotificationContext, event: MonitorNotificationEvent): Promise<void> {
  const monitor = event.monitor;
  try {
    const [webhookRows] = await execQuery(ctx.pool,
      'SELECT key_name, value FROM settings WHERE key_name IN (?, ?, ?)',
      ['webhookUrl', 'webhookMethod', 'webhookHeaders']
    );

    if (webhookRows.length === 0 || !webhookRows.find((r: SettingsRow) => r.key_name === 'webhookUrl' && r.value)) {
      ctx.logger.warn(`Webhook 配置未设置，跳过发送 ${JSON.stringify({monitorId: monitor.id})}`);
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
        } catch {
          config.headers = {};
        }
      }
    });

    if (!config.url) {
      ctx.logger.warn(`Webhook URL 未设置，跳过发送 ${JSON.stringify({monitorId: monitor.id})}`);
      return;
    }

    const method = (config.method || 'POST').toUpperCase();
    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': 'Xilore-Uptime/1.0',
      ...config.headers
    };

    const eventTime = event.timestamp || new Date();
    const payload = {
      event: getNotificationEventName(event),
      action: {
        type: event.type,
        text: getNotificationActionText(event)
      },
      monitor: {
        id: monitor.id,
        name: monitor.name,
        type: monitor.type,
        target: monitor.target,
        port: monitor.port
      },
      status: {
        old: event.oldStatus || 'unknown',
        new: event.type === 'status' ? (event.newStatus || 'unknown') : String(monitor.status || 'unknown'),
        text: event.type === 'status' ? getStatusText(event.newStatus || 'unknown') : getNotificationActionText(event)
      },
      check: {
        responseTime: event.responseTime ?? null,
        message: getNotificationMessage(event),
        timestamp: eventTime.toISOString(),
        time: eventTime.toLocaleString('zh-CN')
      }
    };

    const parsedUrl = new URL(config.url);
    const httpModule = parsedUrl.protocol === 'https:' ? https : http;
    const requestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      headers
    };

    await new Promise((resolve: (v?: void) => void, reject: (e: Error) => void) => {
      const req = httpModule.request(requestOptions, (res: http.IncomingMessage) => {
        let data = '';
        res.on('data', (chunk: Buffer | string) => {
          data += chunk;
        });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            ctx.logger.info(`Webhook 通知发送成功 ${JSON.stringify({monitorId: monitor.id, statusCode: res.statusCode})}`);
            resolve(undefined);
          } else {
            ctx.logger.warn(`Webhook 通知返回非成功状态码 ${JSON.stringify({
              monitorId: monitor.id,
              statusCode: res.statusCode
            })}`);
            resolve(undefined);
          }
        });
      });

      req.on('error', (err: Error) => {
        ctx.logger.error(`Webhook 请求失败 ${JSON.stringify({monitorId: monitor.id, error: err.message})}`);
        reject(err);
      });

      req.setTimeout(10000);
      req.on('timeout', () => {
        req.destroy();
        ctx.logger.error(`Webhook 请求超时 ${JSON.stringify({monitorId: monitor.id})}`);
        reject(new Error('Request timeout'));
      });

      if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        req.write(JSON.stringify(payload));
      }

      req.end();
    });
  } catch (error) {
    ctx.logger.error(`发送 Webhook 通知失败 ${JSON.stringify({monitorId: monitor.id, error: error.message})}`);
    throw error;
  }
}

function buildFeishuSignature(secret: string): { timestamp: string; sign: string } {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const sign = crypto
    .createHmac('sha256', timestamp + '\n' + secret)
    .update('')
    .digest('base64');
  return {timestamp, sign};
}

function buildFeishuCard(event: MonitorNotificationEvent) {
  const monitor = event.monitor;
  const meta = getNotificationMeta(event);
  const statusText = getNotificationActionText(event);
  const oldStatusText = event.type === 'create' ? '无' : getStatusText(event.oldStatus || String(monitor.status || 'unknown'));
  const checkTime = (event.timestamp || new Date()).toLocaleString('zh-CN');

  return {
    config: {
      wide_screen_mode: true
    },
    header: {
      template: meta.template,
      title: {
        tag: 'plain_text',
        content: `Xilore Uptime - ${monitor.name} ${statusText}`
      }
    },
    elements: [
      {
        tag: 'div',
        text: {
          tag: 'lark_md',
          content: [
            `**监控名称：** ${monitor.name}`,
            `**目标地址：** ${getTargetAddress(monitor)}`,
            `**检测类型：** ${String(monitor.type).toUpperCase()}`,
            `**状态变化：** ${oldStatusText} → ${statusText}`,
            `**响应时间：** ${getNotificationResponseTimeText(event)}`,
            `**详情消息：** ${getNotificationMessage(event)}`,
            `**检测时间：** ${checkTime}`
          ].join('\n')
        }
      }
    ]
  };
}

export async function sendFeishuRequest(
  webhookUrl: string,
  secret: string | null | undefined,
  card: unknown,
  logContext: Record<string, unknown>,
  logger?: NotificationLogger
): Promise<{ statusCode: number; body: string; data: any }> {
  const payload: Record<string, unknown> = {
    msg_type: 'interactive',
    card
  };

  if (secret && String(secret).trim()) {
    const signature = buildFeishuSignature(String(secret).trim());
    payload.timestamp = signature.timestamp;
    payload.sign = signature.sign;
  }

  const parsedUrl = new URL(webhookUrl);
  const httpModule = parsedUrl.protocol === 'https:' ? https : http;
  const requestBody = JSON.stringify(payload);
  const requestOptions = {
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
    path: parsedUrl.pathname + parsedUrl.search,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'Xilore-Uptime/1.0',
      'Content-Length': Buffer.byteLength(requestBody)
    }
  };

  return new Promise((resolve: (v: { statusCode: number; body: string; data: any }) => void, reject: (e: Error) => void) => {
    const req = httpModule.request(requestOptions, (res: http.IncomingMessage) => {
      let body = '';
      res.on('data', (chunk: Buffer | string) => {
        body += chunk;
      });
      res.on('end', () => {
        let data = null;
        if (body) {
          try {
            data = JSON.parse(body);
          } catch {
            data = null;
          }
        }
        resolve({statusCode: res.statusCode || 0, body, data});
      });
    });

    req.on('error', (err: Error) => {
      logger?.error(`飞书请求失败 ${JSON.stringify({...logContext, error: err.message})}`);
      reject(err);
    });

    req.setTimeout(10000);
    req.on('timeout', () => {
      req.destroy();
      logger?.error(`飞书请求超时 ${JSON.stringify(logContext)}`);
      reject(new Error('Request timeout'));
    });

    req.write(requestBody);
    req.end();
  });
}

async function sendFeishuNotification(ctx: NotificationContext, event: MonitorNotificationEvent): Promise<void> {
  const monitor = event.monitor;
  try {
    const [feishuRows] = await execQuery(ctx.pool,
      'SELECT key_name, value FROM settings WHERE key_name IN (?, ?)',
      ['feishuWebhookUrl', 'feishuSecret']
    );

    if (feishuRows.length === 0 || !feishuRows.find((r: SettingsRow) => r.key_name === 'feishuWebhookUrl' && r.value)) {
      ctx.logger.warn(`飞书配置未设置，跳过发送 ${JSON.stringify({monitorId: monitor.id})}`);
      return;
    }

    const config: { webhookUrl?: string; secret?: string } = {};
    feishuRows.forEach((row: SettingsRow) => {
      if (row.key_name === 'feishuWebhookUrl') config.webhookUrl = row.value || '';
      else if (row.key_name === 'feishuSecret') config.secret = row.value || '';
    });

    if (!config.webhookUrl) {
      ctx.logger.warn(`飞书 Webhook URL 未设置，跳过发送 ${JSON.stringify({monitorId: monitor.id})}`);
      return;
    }

    const card = buildFeishuCard(event);
    const result = await sendFeishuRequest(config.webhookUrl, config.secret, card, {monitorId: monitor.id, type: event.type}, ctx.logger);

    if (result.statusCode < 200 || result.statusCode >= 300) {
      ctx.logger.warn(`飞书通知返回非成功状态码 ${JSON.stringify({monitorId: monitor.id, statusCode: result.statusCode})}`);
      return;
    }

    if (result.data && typeof result.data.code === 'number' && result.data.code !== 0) {
      ctx.logger.warn(`飞书通知返回失败 ${JSON.stringify({monitorId: monitor.id, code: result.data.code, msg: result.data.msg || result.data.message})}`);
      return;
    }

    ctx.logger.info(`飞书通知发送成功 ${JSON.stringify({monitorId: monitor.id, statusCode: result.statusCode})}`);
  } catch (error) {
    ctx.logger.error(`发送飞书通知失败 ${JSON.stringify({monitorId: monitor.id, error: error.message})}`);
    throw error;
  }
}
