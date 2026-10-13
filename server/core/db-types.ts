/**
 * 数据库表行类型定义，与 schema 保持一致，便于类型推导与重构。
 */

/** monitor_groups 表 */
export interface MonitorGroupRow {
  id: number;
  name: string;
  description?: string | null;
  sort_order?: number;
  created_at?: Date | string;
}

/** monitors 表 */
export interface MonitorRow {
  id: number;
  name: string;
  type: 'http' | 'tcp' | 'ping';
  target: string;
  port?: number | null;
  interval_seconds?: number;
  timeout_seconds?: number;
  retries?: number;
  expected_status?: number;
  group_id?: number | null;
  status?: 'up' | 'down' | 'unknown';
  last_check?: Date | string | null;
  last_response_time?: number | null;
  /** HTTPS 证书剩余有效天数，仅 type=http 且目标为 https 时有值 */
  ssl_days_remaining?: number | null;
  created_at?: Date | string;
  enabled?: number;
  is_public?: number;
  email_notification?: number;
  webhook_notification?: number;
  feishu_notification?: number;
  auth_username?: string | null;
  auth_password?: string | null;
  /** SELECT 计算字段等 */
  [key: string]: unknown;
}

/** check_history 表 */
export interface CheckHistoryRow {
  id: number;
  monitor_id: number;
  status: 'up' | 'down' | 'warning';
  response_time?: number | null;
  message?: string | null;
  checked_at?: Date | string;
  in_maintenance?: number;
  stats_excluded?: number;
}

export type ContentChannel = 'email' | 'webhook' | 'feishu';

export interface AnnouncementRow {
  id: number;
  title: string;
  body: string;
  state: 'draft' | 'published' | 'archived';
  pinned: number;
  channels: string;
  revision: number;
  published_ms: number | null;
  created_ms: number;
  updated_ms: number;
}

/** 时间使用 UTC epoch 毫秒，避免 MySQL session 和进程时区差异。 */
export interface MaintenanceRow {
  id: number;
  title: string;
  body: string;
  starts_ms: number;
  ends_ms: number | null;
  cancelled_ms: number | null;
  continue_checks: number;
  suppress_alerts: number;
  exclude_stats: number;
  is_public: number;
  channels: string;
  revision: number;
  phase: 'scheduled' | 'active' | 'completed' | 'cancelled';
  created_ms: number;
  updated_ms: number;
}

export interface MaintenanceMembership extends MaintenanceRow {
  monitor_id: number;
}

/** maintenance_runtime 表；保留跨进程的静默基线及待复检状态。 */
export interface MaintenanceRuntimeRow {
  monitor_id: number;
  silenced: number;
  checks_paused: number;
  baseline_status: CheckHistoryRow['status'] | 'unknown' | null;
  recheck_pending: number;
  observed_ms: number | null;
}

/** maintenance_monitors 表，保存创建或预约编辑时选择的具体监控集合。 */
export interface MaintenanceMonitorRow {
  maintenance_id: number;
  monitor_id: number;
}

export interface ContentDeliveryRow {
  id: number;
  event_key: string;
  owner_type: 'announcement' | 'maintenance' | 'monitor';
  owner_id: number;
  channel: ContentChannel;
  payload: string;
  state: 'pending' | 'sending' | 'sent' | 'failed' | 'skipped';
  attempts: number;
  next_attempt_ms: number;
  lease_until_ms: number | null;
  last_error: string | null;
}

/** settings 表 */
export interface SettingsRow {
  id?: number;
  key_name: string;
  value: string | null;
  updated_at?: Date | string;
}

/** 聚合查询：按 monitor 的 uptime 统计（如 24h 内 up_checks/total_checks） */
export interface UptimeAggRow {
  monitor_id: number;
  total_checks: number;
  up_checks: number;
}
