import mysql, { type RowDataPacket } from "mysql2/promise";
import { getLogger } from "xilore-log4js";
import { createDatabaseClient, type DatabaseClient } from './db-utils.js';
import { assertWritable, isUiDevMode } from './runtime-mode.js';

const logger = getLogger("database");

export interface DatabaseConfig {
  host: string;
  port?: number;
  user: string;
  password: string;
  name: string;
}

export interface AppConfigWithDatabase {
  database: DatabaseConfig;
}

interface ColumnRow extends RowDataPacket {
  Field: string;
}

export async function connectDatabase(
  config: AppConfigWithDatabase
): Promise<DatabaseClient> {
  if (!config || !config.database) {
    throw new Error("数据库配置不存在");
  }

  const pool = mysql.createPool({
    host: config.database.host,
    port: config.database.port || 3306,
    user: config.database.user,
    password: config.database.password,
    database: config.database.name,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    multipleStatements: false,
  });

  const client = createDatabaseClient(pool, isUiDevMode());
  try {
    await client.execute('SELECT 1');
    return client;
  } catch (error) {
    await client.end();
    throw error;
  }
}

/** 只读模式只检查兼容性，不尝试建表或补列。 */
export async function validateExistingDatabase(pool: DatabaseClient): Promise<void> {
  const requiredColumns = {
    users: 'id, username, password, email, role, created_at',
    monitor_groups: 'id, name, description, sort_order, created_at',
    monitors: 'id, name, type, target, port, interval_seconds, timeout_seconds, retries, expected_status, group_id, status, last_check, last_response_time, ssl_days_remaining, created_at, enabled, is_public, email_notification, webhook_notification, feishu_notification, auth_username, auth_password',
    check_history: 'id, monitor_id, status, response_time, message, checked_at, in_maintenance, stats_excluded',
    announcements: 'id, title, body, state, pinned, channels, revision, published_ms, created_ms, updated_ms',
    maintenances: 'id, title, body, starts_ms, ends_ms, cancelled_ms, continue_checks, suppress_alerts, exclude_stats, is_public, channels, phase, revision, created_ms, updated_ms',
    maintenance_monitors: 'maintenance_id, monitor_id',
    maintenance_runtime: 'monitor_id, silenced, checks_paused, baseline_status, recheck_pending, observed_ms',
    content_deliveries: 'id, event_key, owner_type, owner_id, channel, payload, state, attempts, next_attempt_ms, lease_until_ms, last_error',
    settings: 'id, key_name, value, updated_at'
  };
  for (const [table, columns] of Object.entries(requiredColumns)) {
    try {
      await pool.execute(`SELECT ${columns} FROM ${table} LIMIT 0`);
    } catch (error) {
      throw new Error(`UI 开发模式要求兼容的已有表结构，检查 ${table} 失败：${(error as Error).message}`);
    }
  }
  const [rows] = await pool.execute('SELECT COUNT(*) as count FROM users WHERE role = ?', ['admin']);
  if (!Number(rows[0]?.count)) throw new Error('UI 开发模式要求数据库中已有管理员账号');
}

/** 安装向导的连接测试会建库，必须在创建任何连接之前检查运行模式。 */
export async function testDatabaseConnection(database: DatabaseConfig): Promise<{ initialized: boolean; hasAdmin: boolean; adminCount: number }> {
  assertWritable();
  const testPool = mysql.createPool({
    host: database.host, port: database.port || 3306, user: database.user,
    password: database.password, waitForConnections: true, connectionLimit: 1,
    multipleStatements: false
  });
  try {
    const conn = await testPool.getConnection();
    try {
      await conn.query('CREATE DATABASE IF NOT EXISTS ?? CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci', [database.name]);
      await conn.query('USE ??', [database.name]);
      const [tables] = await conn.query<RowDataPacket[]>("SHOW TABLES LIKE 'users'");
      if (tables.length === 0) return {initialized: false, hasAdmin: false, adminCount: 0};
      const [admins] = await conn.query<RowDataPacket[]>('SELECT COUNT(*) as count FROM users WHERE role = ?', ['admin']);
      const adminCount = Number(admins[0].count);
      return {initialized: true, hasAdmin: adminCount > 0, adminCount};
    } finally {
      conn.release();
    }
  } finally {
    await testPool.end();
  }
}

export async function initializeTables(pool: DatabaseClient): Promise<void> {
  assertWritable();
  const createUsersTable = `
      CREATE TABLE IF NOT EXISTS users
      (
          id         INT AUTO_INCREMENT PRIMARY KEY,
          username   VARCHAR(50)  NOT NULL UNIQUE,
          password   VARCHAR(255) NOT NULL,
          email      VARCHAR(100),
          role       ENUM ('admin', 'user') DEFAULT 'user',
          created_at TIMESTAMP              DEFAULT CURRENT_TIMESTAMP
      )
  `;

  const createGroupsTable = `
      CREATE TABLE IF NOT EXISTS monitor_groups
      (
          id          INT AUTO_INCREMENT PRIMARY KEY,
          name        VARCHAR(100) NOT NULL,
          description VARCHAR(255),
          sort_order  INT       DEFAULT 0,
          created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
  `;

  const createMonitorsTable = `
      CREATE TABLE IF NOT EXISTS monitors
      (
          id                 INT AUTO_INCREMENT PRIMARY KEY,
          name               VARCHAR(100)                 NOT NULL,
          type               ENUM ('http', 'tcp', 'ping') NOT NULL,
          target             VARCHAR(255)                 NOT NULL,
          port               INT,
          interval_seconds   INT                            DEFAULT 60,
          timeout_seconds    INT                            DEFAULT 10,
          retries            INT                            DEFAULT 0,
          expected_status    INT                            DEFAULT 200,
          group_id           INT                            DEFAULT NULL,
          status             ENUM ('up', 'down', 'unknown') DEFAULT 'unknown',
          last_check         TIMESTAMP                    NULL,
          last_response_time INT,
          ssl_days_remaining INT                            DEFAULT NULL,
          created_at         TIMESTAMP                      DEFAULT CURRENT_TIMESTAMP,
          enabled            TINYINT(1)                     DEFAULT 1,
          is_public          TINYINT(1)                     DEFAULT 0
      )
  `;

  const createHistoryTable = `
      CREATE TABLE IF NOT EXISTS check_history
      (
          id            INT AUTO_INCREMENT PRIMARY KEY,
          monitor_id    INT                            NOT NULL,
          status        ENUM ('up', 'down', 'warning') NOT NULL,
          response_time INT,
          message       VARCHAR(255),
          checked_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_monitor (monitor_id),
          INDEX idx_time (checked_at),
          FOREIGN KEY (monitor_id) REFERENCES monitors (id) ON DELETE CASCADE
      )
  `;

  const alterHistoryTable = `
      ALTER TABLE check_history
          MODIFY COLUMN status ENUM ('up', 'down', 'warning') NOT NULL
  `;

  const createSettingsTable = `
      CREATE TABLE IF NOT EXISTS settings
      (
          id         INT AUTO_INCREMENT PRIMARY KEY,
          key_name   VARCHAR(100) NOT NULL UNIQUE,
          value      TEXT,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
  `;

  await pool.execute(createUsersTable);
  await pool.execute(createGroupsTable);
  await pool.execute(createMonitorsTable);
  await pool.execute(createHistoryTable);
  await pool.execute(createSettingsTable);

  try {
    await pool.execute(alterHistoryTable);
    logger.info("✓ check_history表结构已更新，添加warning状态");
  } catch (e: unknown) {
    const err = e as Error;
    if (
      err.message &&
      !err.message.includes("Duplicate") &&
      !err.message.includes("doesn't exist")
    ) {
      logger.error("更新check_history表结构失败:", err);
    }
  }

  try {
    const [columns] = (await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'timeout_ms'"
    )) as [ColumnRow[], unknown];
    if (Array.isArray(columns) && columns.length > 0) {
      // noinspection SqlResolve
      await pool.execute(
        "ALTER TABLE monitors CHANGE timeout_ms timeout_seconds INT DEFAULT 10"
      );
      await pool.execute(
        "UPDATE monitors SET timeout_seconds = CEIL(timeout_seconds / 1000)"
      );
    }
  } catch {
    // 忽略迁移错误
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'retries'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN retries INT DEFAULT 0 AFTER timeout_seconds"
      );
      logger.info("✓ 已添加 retries 列");
    }
  } catch {
    // 忽略迁移错误
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'email_notification'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN email_notification TINYINT(1) DEFAULT 0 AFTER is_public"
      );
      logger.info("✓ 已添加 email_notification 列");
    }
  } catch (e: unknown) {
    logger.error("添加 email_notification 列失败:", e as Error);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'webhook_notification'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN webhook_notification TINYINT(1) DEFAULT 0 AFTER email_notification"
      );
      logger.info("✓ 已添加 webhook_notification 列");
    }
  } catch (e: unknown) {
    logger.error("添加 webhook_notification 列失败:", e as Error);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'feishu_notification'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN feishu_notification TINYINT(1) DEFAULT 0 AFTER webhook_notification"
      );
      logger.info("✓ 已添加 feishu_notification 列");
    }
  } catch (e: unknown) {
    logger.error("添加 feishu_notification 列失败:", e as Error);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'expected_status'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN expected_status INT DEFAULT 200 AFTER retries"
      );
      logger.info("✓ 已添加 expected_status 列");
    }
  } catch (e: unknown) {
    logger.error("添加 expected_status 列失败:", e as Error);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'group_id'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      const [allColumns] = (await pool.execute(
        "SHOW COLUMNS FROM monitors"
      )) as [ColumnRow[], unknown];
      const rows = Array.isArray(allColumns) ? allColumns : [];
      let afterColumn = "expected_status";
      const hasExpectedStatus = rows.some((col) => col.Field === "expected_status");
      const hasRetries = rows.some((col) => col.Field === "retries");
      if (!hasExpectedStatus) {
        afterColumn = hasRetries ? "retries" : "timeout_seconds";
      }
      const validColumns = ["expected_status", "retries", "timeout_seconds"];
      if (!validColumns.includes(afterColumn)) {
        afterColumn = "timeout_seconds";
      }
      await pool.execute(
        `ALTER TABLE monitors
            ADD COLUMN group_id INT DEFAULT NULL AFTER ${afterColumn}`
      );
      logger.info(`✓ 已添加 group_id 列（位置：${afterColumn} 之后）`);
    } else {
      logger.info("✓ group_id 列已存在");
    }
  } catch (e: unknown) {
    const err = e as Error;
    logger.error("添加 group_id 列失败:", err);
    if (err.message?.includes("Duplicate column name")) {
      logger.info("  (列已存在，忽略此错误)");
    }
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitor_groups LIKE 'sort_order'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitor_groups ADD COLUMN sort_order INT DEFAULT 0 AFTER description"
      );
      logger.info("✓ 已添加 monitor_groups.sort_order 列");
    } else {
      logger.info("✓ monitor_groups.sort_order 列已存在");
    }
  } catch (e: unknown) {
    logger.error("添加 monitor_groups.sort_order 列失败:", e as Error);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'is_public'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN is_public TINYINT(1) DEFAULT 0 AFTER enabled"
      );
      logger.info("✓ 已添加 monitors.is_public 列");
    } else {
      logger.info("✓ monitors.is_public 列已存在");
    }
  } catch (e: unknown) {
    logger.error("添加 monitors.is_public 列失败:", e as Error);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'auth_username'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN auth_username VARCHAR(255) DEFAULT NULL AFTER is_public"
      );
      logger.info("✓ 已添加 auth_username 列");
    } else {
      logger.info("✓ monitors.auth_username 列已存在");
    }
  } catch (e: unknown) {
    logger.error("添加 monitors.auth_username 列失败:", e as Error);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'auth_password'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN auth_password VARCHAR(255) DEFAULT NULL AFTER auth_username"
      );
      logger.info("✓ 已添加 auth_password 列");
    } else {
      logger.info("✓ monitors.auth_password 列已存在");
    }
  } catch (e: unknown) {
    logger.error("添加 monitors.auth_password 列失败:", e as Error);
  }

  try {
    const [columns] = (await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'ssl_days_remaining'"
    )) as [ColumnRow[], unknown];
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN ssl_days_remaining INT DEFAULT NULL AFTER last_response_time"
      );
      logger.info("✓ 已添加 monitors.ssl_days_remaining 列");
    } else {
      logger.info("✓ monitors.ssl_days_remaining 列已存在");
    }
  } catch (e: unknown) {
    const err = e as Error;
    logger.error("添加 monitors.ssl_days_remaining 列失败:", err);
  }

  try {
    const [tables] = await pool.execute("SHOW TABLES LIKE 'monitor_groups'");
    if (Array.isArray(tables) && tables.length === 0) {
      logger.warn("⚠ monitor_groups 表不存在，但应该已创建");
    } else {
      logger.info("✓ monitor_groups 表已存在");
    }
  } catch (e: unknown) {
    logger.error("检查 monitor_groups 表失败:", e as Error);
  }

  await initializeCommunicationTables(pool);
  logger.info("数据表初始化完成");
}

/** 可重复执行；新增表结构失败必须向上传播，避免以不完整的维护保护启动检测。 */
export async function initializeCommunicationTables(pool: DatabaseClient): Promise<void> {
  assertWritable();
  await pool.execute(`CREATE TABLE IF NOT EXISTS announcements (
    id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(200) NOT NULL, body MEDIUMTEXT NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'draft', pinned TINYINT NOT NULL DEFAULT 0,
    channels VARCHAR(100) NOT NULL DEFAULT '[]', revision INT NOT NULL DEFAULT 1,
    published_ms BIGINT NULL, created_ms BIGINT NOT NULL, updated_ms BIGINT NOT NULL,
    INDEX idx_announcement_state (state, published_ms)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
  await pool.execute(`CREATE TABLE IF NOT EXISTS maintenances (
    id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(200) NOT NULL, body MEDIUMTEXT NOT NULL,
    starts_ms BIGINT NOT NULL, ends_ms BIGINT NULL, cancelled_ms BIGINT NULL,
    continue_checks TINYINT NOT NULL DEFAULT 1, suppress_alerts TINYINT NOT NULL DEFAULT 1,
    exclude_stats TINYINT NOT NULL DEFAULT 1, is_public TINYINT NOT NULL DEFAULT 0,
    channels VARCHAR(100) NOT NULL DEFAULT '[]', revision INT NOT NULL DEFAULT 1,
    phase VARCHAR(16) NOT NULL DEFAULT 'scheduled', created_ms BIGINT NOT NULL, updated_ms BIGINT NOT NULL,
    INDEX idx_maintenance_time (starts_ms, ends_ms)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
  await pool.execute(`CREATE TABLE IF NOT EXISTS maintenance_monitors (
    maintenance_id INT NOT NULL, monitor_id INT NOT NULL, PRIMARY KEY (maintenance_id, monitor_id),
    INDEX idx_maintenance_monitor (monitor_id),
    FOREIGN KEY (maintenance_id) REFERENCES maintenances(id) ON DELETE CASCADE,
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
  await pool.execute(`CREATE TABLE IF NOT EXISTS maintenance_runtime (
    monitor_id INT PRIMARY KEY, silenced TINYINT NOT NULL DEFAULT 0,
    checks_paused TINYINT NOT NULL DEFAULT 0, baseline_status VARCHAR(16) NULL,
    recheck_pending TINYINT NOT NULL DEFAULT 0, observed_ms BIGINT NULL,
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
  await pool.execute(`CREATE TABLE IF NOT EXISTS content_deliveries (
    id INT AUTO_INCREMENT PRIMARY KEY, event_key VARCHAR(150) NOT NULL,
    owner_type VARCHAR(20) NOT NULL, owner_id INT NOT NULL, channel VARCHAR(16) NOT NULL,
    payload MEDIUMTEXT NOT NULL, state VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0, next_attempt_ms BIGINT NOT NULL,
    lease_until_ms BIGINT NULL, last_error VARCHAR(255) NULL,
    UNIQUE KEY uq_content_delivery (event_key, channel), INDEX idx_delivery_due (state, next_attempt_ms)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
  for (const column of ['in_maintenance', 'stats_excluded']) {
    const [rows] = await pool.execute(`SHOW COLUMNS FROM check_history LIKE '${column}'`);
    if (!rows.length) await pool.execute(`ALTER TABLE check_history ADD COLUMN ${column} TINYINT NOT NULL DEFAULT 0`);
  }
}
