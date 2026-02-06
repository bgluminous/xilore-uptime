/**
 * 数据库表行类型定义，与 schema 保持一致，便于类型推导与重构。
 */

/** users 表 */
export interface UserRow {
  id: number;
  username: string;
  password: string;
  email: string | null;
  role: 'admin' | 'user';
  created_at?: Date | string;
}

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
  created_at?: Date | string;
  enabled?: number;
  is_public?: number;
  email_notification?: number;
  webhook_notification?: number;
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
