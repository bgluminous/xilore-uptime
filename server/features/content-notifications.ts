import http from 'node:http';
import https from 'node:https';
import nodemailer from 'nodemailer';
import {getLogger} from 'xilore-log4js';
import type {DatabaseExecutor} from '../core/db-utils.js';
import type {ContentChannel, ContentDeliveryRow} from '../core/db-types.js';
import {assertWritable} from '../core/runtime-mode.js';
import {escapeHtml} from '../core/templates.js';
import {sendFeishuRequest, sendMonitorNotificationChannel, type MonitorNotificationEvent} from './notifications.js';
import {parseChannels, renderContent} from './content.js';

export interface ContentEvent {
  event: string;
  event_id: string;
  title: string;
  body: string;
  timestamp: string;
  starts_at?: string;
  ends_at?: string | null;
  monitor_event?: MonitorNotificationEvent;
}

const eventLabels: Record<string, string> = {
  announcement_published: '公告发布', maintenance_scheduled: '维护预约',
  maintenance_started: '维护开始', maintenance_completed: '维护结束',
  maintenance_cancelled: '维护取消', maintenance_rescheduled: '维护改期'
};

export async function enqueueContentEvent(
  db: DatabaseExecutor, ownerType: 'announcement' | 'maintenance',
  row: {id: number; title: string; body: string; channels: string; revision: number;
    starts_ms?: number; ends_ms?: number | null}, event: string, now: number
): Promise<void> {
  assertWritable();
  const eventKey = `${ownerType}:${row.id}:${row.revision}:${event}`;
  const payload: ContentEvent = {
    event, event_id: eventKey, title: row.title, body: row.body, timestamp: new Date(now).toISOString()
  };
  if (row.starts_ms != null) {
    payload.starts_at = new Date(Number(row.starts_ms)).toISOString();
    payload.ends_at = row.ends_ms == null ? null : new Date(Number(row.ends_ms)).toISOString();
  }
  for (const channel of parseChannels(row.channels)) {
    await db.execute(`INSERT INTO content_deliveries
      (event_key, owner_type, owner_id, channel, payload, next_attempt_ms)
      VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE event_key = VALUES(event_key)`,
    [eventKey, ownerType, row.id, channel, JSON.stringify(payload), now]);
  }
}

/** 首检结果与待投递事件原子保存，进程中断后仍能按原有监控通知格式继续投递。 */
export async function enqueueMaintenanceRecheck(db: DatabaseExecutor, event: MonitorNotificationEvent, historyId: number, now: number): Promise<void> {
  assertWritable();
  const monitor = event.monitor;
  // 清空历史可能重置自增编号，检测时间也参与标识，避免后续首检误命中旧事件。
  const eventKey = `monitor:${monitor.id}:${historyId}:${now}:maintenance_recheck`;
  const snapshot = {...event, monitor: {id: monitor.id, name: monitor.name, type: monitor.type,
    target: monitor.target, port: monitor.port, status: monitor.status}};
  const payload: ContentEvent = {event: 'monitor_maintenance_recheck', event_id: eventKey,
    title: monitor.name, body: event.message || '', timestamp: new Date(now).toISOString(), monitor_event: snapshot};
  for (const channel of ['email', 'webhook', 'feishu'] as ContentChannel[]) {
    if (!monitor[`${channel}_notification`]) continue;
    await db.execute(`INSERT INTO content_deliveries
      (event_key, owner_type, owner_id, channel, payload, next_attempt_ms)
      VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE event_key = VALUES(event_key)`,
    [eventKey, 'monitor', monitor.id, channel, JSON.stringify(payload), now]);
  }
}

function sendWebhook(url: string, method: string, headers: Record<string, string>, payload: ContentEvent): Promise<void> {
  const target = new URL(url);
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Webhook 协议不受支持');
  return new Promise((resolve, reject) => {
    const request = (target.protocol === 'https:' ? https : http).request(target, {
      method, headers: {...headers, 'Content-Type': 'application/json', 'Idempotency-Key': payload.event_id}
    }, response => {
      response.resume();
      response.on('end', () => (response.statusCode >= 200 && response.statusCode < 300)
        ? resolve() : reject(new Error(`Webhook 返回 HTTP ${response.statusCode}`)));
      response.on('error', () => reject(new Error('Webhook 响应中断')));
    });
    request.on('error', () => reject(new Error('Webhook 连接失败')));
    request.setTimeout(10000, () => request.destroy(new Error('Webhook 超时')));
    request.end(['POST', 'PUT', 'PATCH'].includes(method) ? JSON.stringify(payload) : undefined);
  });
}

/** 使用相同的配置与接收方；新增事件不改变已有监控通知的负载。 */
export async function sendContentNotification(db: DatabaseExecutor, channel: ContentChannel, event: ContentEvent): Promise<void> {
  assertWritable();
  if (event.monitor_event) {
    await sendMonitorNotificationChannel({pool: db, logger: getLogger('maintenance-notifications')},
      {...event.monitor_event, timestamp: new Date(String(event.monitor_event.timestamp))}, channel);
    return;
  }
  const [rows] = await db.execute('SELECT key_name, value FROM settings');
  const config = Object.fromEntries(rows.map(row => [row.key_name, row.value]));
  const title = `${eventLabels[event.event] || '服务通知'}：${event.title}`;
  const timeText = event.starts_at ? `维护时间：${event.starts_at} 至 ${event.ends_at || '手动结束'}` : '';
  if (channel === 'email') {
    const [admins] = await db.execute('SELECT email FROM users WHERE role = ? LIMIT 1', ['admin']);
    if (!admins[0]?.email || !config.smtpHost || !config.smtpUser || !config.smtpPassword || !config.smtpFrom) {
      throw new Error('邮件配置或管理员邮箱不完整');
    }
    const transporter = (nodemailer as any).createTransport({
      host: config.smtpHost, port: Number(config.smtpPort) || 587,
      secure: ['1', 'true'].includes(config.smtpSecure),
      auth: {user: config.smtpUser, pass: config.smtpPassword},
      connectionTimeout: 15000, greetingTimeout: 15000, socketTimeout: 20000
    });
    try {
      await transporter.sendMail({from: config.smtpFrom, to: admins[0].email, subject: title,
        text: `${title}\n${timeText}\n${event.body}`,
        html: `<h2>${escapeHtml(title)}</h2><p>${escapeHtml(timeText)}</p>${renderContent(event.body)}`});
    } catch { throw new Error('邮件发送失败，请检查配置或服务连接'); }
    finally { transporter.close(); }
  } else if (channel === 'webhook') {
    if (!config.webhookUrl) throw new Error('未配置 Webhook');
    let headers: Record<string, string>;
    try { headers = JSON.parse(config.webhookHeaders || '{}'); }
    catch { throw new Error('Webhook 请求头格式错误'); }
    await sendWebhook(config.webhookUrl, (config.webhookMethod || 'POST').toUpperCase(), headers, event);
  } else {
    if (!config.feishuWebhookUrl) throw new Error('未配置飞书');
    let response;
    try {
      response = await sendFeishuRequest(config.feishuWebhookUrl, config.feishuSecret, {
        header: {template: 'blue', title: {tag: 'plain_text', content: title}},
        elements: [{tag: 'div', text: {tag: 'plain_text', content: `${timeText}\n${event.body}`.slice(0, 10000)}}]
      }, {eventId: event.event_id});
    } catch { throw new Error('飞书连接失败'); }
    if (response.statusCode < 200 || response.statusCode >= 300 || response.data?.code !== 0) {
      throw new Error('飞书拒绝通知，请检查机器人配置');
    }
  }
}

/** 初次投递加三次重试；租约允许进程中断后继续。外部服务不支持幂等时可能重复接收。 */
export async function processContentDeliveries(
  db: DatabaseExecutor, now = Date.now(),
  send: (db: DatabaseExecutor, channel: ContentChannel, event: ContentEvent) => Promise<void> = sendContentNotification,
  clock?: () => number
): Promise<void> {
  assertWritable();
  const began = Date.now();
  const currentTime = clock || (() => now + Date.now() - began);
  await db.execute(`UPDATE content_deliveries SET state = 'failed', lease_until_ms = NULL,
    last_error = '投递中断且重试次数已耗尽'
    WHERE state = 'sending' AND lease_until_ms <= ? AND attempts >= 4`, [now]);
  const [rows]: [ContentDeliveryRow[], unknown] = await db.execute(`SELECT * FROM content_deliveries
    WHERE attempts < 4 AND ((state = 'pending' AND next_attempt_ms <= ?)
      OR (state = 'sending' AND lease_until_ms <= ?)) ORDER BY id LIMIT 10`, [now, now]);
  for (const row of rows) {
    const claimedAt = currentTime();
    const attempt = Number(row.attempts) + 1;
    const [claim] = await db.execute(`UPDATE content_deliveries SET state = 'sending',
      attempts = attempts + 1, lease_until_ms = ? WHERE id = ? AND attempts = ?
      AND ((state = 'pending' AND next_attempt_ms <= ?) OR (state = 'sending' AND lease_until_ms <= ?))`,
    [claimedAt + 120000, row.id, row.attempts, claimedAt, claimedAt]);
    if (!claim.affectedRows) continue;
    try {
      const event: ContentEvent = JSON.parse(row.payload);
      let obsolete = false;
      if (event.event === 'announcement_published') {
        const [announcements] = await db.execute('SELECT state FROM announcements WHERE id = ?', [row.owner_id]);
        obsolete = !announcements[0] || announcements[0].state === 'draft';
      }
      if (event.event === 'maintenance_started') {
        const [maintenance] = await db.execute('SELECT ends_ms, cancelled_ms FROM maintenances WHERE id = ?', [row.owner_id]);
        if (!maintenance[0] || maintenance[0].cancelled_ms != null ||
            (maintenance[0].ends_ms != null && Number(maintenance[0].ends_ms) <= currentTime())) obsolete = true;
      }
      if (event.monitor_event) {
        const checkTime = currentTime();
        const [silencing] = await db.execute(`SELECT mt.id FROM maintenances mt
          INNER JOIN maintenance_monitors mm ON mm.maintenance_id = mt.id
          WHERE mm.monitor_id = ? AND mt.cancelled_ms IS NULL AND mt.suppress_alerts = 1
            AND mt.starts_ms <= ? AND (mt.ends_ms IS NULL OR mt.ends_ms > ?) LIMIT 1`,
        [row.owner_id, checkTime, checkTime]);
        // 新静默期已经开始时丢弃旧首检事件，下一次解除静默后重新检测并生成事件。
        if (silencing.length) obsolete = true;
      }
      if (obsolete) {
        await db.execute("UPDATE content_deliveries SET state = 'skipped', lease_until_ms = NULL WHERE id = ? AND attempts = ? AND state = 'sending'", [row.id, attempt]);
        continue;
      }
      await send(db, row.channel, event);
      await db.execute("UPDATE content_deliveries SET state = 'sent', lease_until_ms = NULL, last_error = NULL WHERE id = ? AND attempts = ? AND state = 'sending'", [row.id, attempt]);
    } catch (error) {
      await db.execute(`UPDATE content_deliveries SET state = ?, lease_until_ms = NULL,
        next_attempt_ms = ?, last_error = ? WHERE id = ? AND attempts = ? AND state = 'sending'`,
      [attempt >= 4 ? 'failed' : 'pending', currentTime() + [30000, 120000, 300000][Math.min(attempt - 1, 2)],
        '通知投递失败；请检查渠道配置、接收地址及网络', row.id, attempt]);
    }
  }
}
