import {DatabaseSync} from 'node:sqlite';
import type {DatabaseClient, DatabaseExecutor} from '../../server/core/db-utils.js';

/** 合成数据专用，执行真实关系查询和事务；不读取配置，也不会连接 MySQL。 */
export function communicationDb() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.function('IF', (condition, yes, no) => condition ? yes : no);
  sqlite.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE monitor_groups (id INTEGER PRIMARY KEY, name TEXT, sort_order INTEGER DEFAULT 0);
    CREATE TABLE monitors (id INTEGER PRIMARY KEY, name TEXT, type TEXT DEFAULT 'http', target TEXT,
      status TEXT DEFAULT 'up', enabled INTEGER DEFAULT 1, is_public INTEGER DEFAULT 1, group_id INTEGER,
      last_check INTEGER, last_response_time INTEGER, interval_seconds INTEGER DEFAULT 60,
      timeout_seconds INTEGER DEFAULT 1, retries INTEGER DEFAULT 0, expected_status INTEGER DEFAULT 200,
      ssl_days_remaining INTEGER, email_notification INTEGER DEFAULT 0, webhook_notification INTEGER DEFAULT 0,
      feishu_notification INTEGER DEFAULT 0, auth_username TEXT, auth_password TEXT, created_at INTEGER DEFAULT 0);
    CREATE TABLE check_history (id INTEGER PRIMARY KEY, monitor_id INTEGER REFERENCES monitors(id) ON DELETE CASCADE,
      status TEXT, response_time INTEGER, message TEXT, checked_at INTEGER, in_maintenance INTEGER DEFAULT 0,
      stats_excluded INTEGER DEFAULT 0);
    CREATE TABLE announcements (id INTEGER PRIMARY KEY, title TEXT, body TEXT, state TEXT DEFAULT 'draft',
      pinned INTEGER DEFAULT 0, channels TEXT DEFAULT '[]', revision INTEGER DEFAULT 1,
      published_ms INTEGER, created_ms INTEGER, updated_ms INTEGER);
    CREATE TABLE maintenances (id INTEGER PRIMARY KEY, title TEXT, body TEXT, starts_ms INTEGER, ends_ms INTEGER,
      cancelled_ms INTEGER, continue_checks INTEGER DEFAULT 1, suppress_alerts INTEGER DEFAULT 1,
      exclude_stats INTEGER DEFAULT 1, is_public INTEGER DEFAULT 0, channels TEXT DEFAULT '[]',
      revision INTEGER DEFAULT 1, phase TEXT DEFAULT 'scheduled', created_ms INTEGER, updated_ms INTEGER);
    CREATE TABLE maintenance_monitors (maintenance_id INTEGER REFERENCES maintenances(id) ON DELETE CASCADE,
      monitor_id INTEGER REFERENCES monitors(id) ON DELETE CASCADE, PRIMARY KEY (maintenance_id, monitor_id));
    CREATE TABLE maintenance_runtime (monitor_id INTEGER PRIMARY KEY REFERENCES monitors(id) ON DELETE CASCADE,
      silenced INTEGER DEFAULT 0, checks_paused INTEGER DEFAULT 0, baseline_status TEXT,
      recheck_pending INTEGER DEFAULT 0, observed_ms INTEGER);
    CREATE TABLE content_deliveries (id INTEGER PRIMARY KEY, event_key TEXT, owner_type TEXT, owner_id INTEGER,
      channel TEXT, payload TEXT, state TEXT DEFAULT 'pending', attempts INTEGER DEFAULT 0,
      next_attempt_ms INTEGER, lease_until_ms INTEGER, last_error TEXT, UNIQUE(event_key, channel));
    CREATE TABLE settings (key_name TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT);
    INSERT INTO monitor_groups VALUES (1, '核心服务', 0), (2, '后台任务', 1);
    INSERT INTO monitors (id, name, target, group_id, is_public) VALUES
      (1, '公开 API', 'https://public.example.invalid', 1, 1),
      (2, '私有数据库', 'private.example.invalid:5432', 1, 0),
      (3, '公开网站', 'https://site.example.invalid', 2, 1),
      (4, '已暂停服务', 'https://paused.example.invalid', 2, 1);
    UPDATE monitors SET enabled = 0 WHERE id = 4;
  `);
  const calls: {sql: string; values: any[]}[] = [];
  const execute: DatabaseExecutor['execute'] = async (sql, values = []) => {
    calls.push({sql, values});
    const normalized = sql.replace(/\s+FOR UPDATE\b/gi, '')
      .replace(/ON DUPLICATE KEY UPDATE (\w+) = VALUES\(\1\)/gi, 'ON CONFLICT DO NOTHING')
      .replace(/DATE_SUB\(NOW\(\), INTERVAL (\d+) (HOUR|DAY)\)/gi,
        (_, count, unit) => String(Date.now() - Number(count) * (unit.toUpperCase() === 'DAY' ? 86400000 : 3600000)));
    const parameters = values.map(value => value instanceof Date ? value.getTime() : typeof value === 'boolean' ? Number(value) : value);
    try {
      const statement = sqlite.prepare(normalized);
      if (/^\s*(SELECT|PRAGMA)/i.test(normalized)) return [statement.all(...parameters).map(row => ({...row})), []];
      const result = statement.run(...parameters);
      return [{insertId: Number(result.lastInsertRowid), affectedRows: Number(result.changes)}, []];
    } catch (error) { throw new Error(`Fixture SQL failed: ${sql}`, {cause: error}); }
  };
  let queue = Promise.resolve();
  const db: DatabaseClient = {
    execute,
    transaction<T>(run: (tx: DatabaseExecutor) => Promise<T>): Promise<T> {
      const result = queue.then(async () => {
        sqlite.exec('BEGIN');
        try { const value = await run({execute}); sqlite.exec('COMMIT'); return value; }
        catch (error) { sqlite.exec('ROLLBACK'); throw error; }
      });
      queue = result.then(() => {}, () => {});
      return result;
    },
    async end() { await queue; sqlite.close(); }
  };
  return {db, calls};
}
