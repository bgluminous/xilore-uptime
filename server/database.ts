import mysql, {Pool, RowDataPacket} from "mysql2/promise";

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
): Promise<Pool> {
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
  });

  // noinspection JSVoidFunctionReturnValueUsed,ES6RedundantAwait
  const conn = await pool.getConnection();
  conn.release();

  return pool;
}

export async function initializeTables(pool: Pool): Promise<void> {
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
    console.log("✓ check_history表结构已更新，添加warning状态");
  } catch (e: unknown) {
    const err = e as Error;
    if (
      err.message &&
      !err.message.includes("Duplicate") &&
      !err.message.includes("doesn't exist")
    ) {
      console.error("更新check_history表结构失败:", err.message);
    }
  }

  try {
    const [columns] = (await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'timeout_ms'"
    )) as [ColumnRow[], unknown];
    if (Array.isArray(columns) && columns.length > 0) {
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
      console.log("✓ 已添加 retries 列");
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
      console.log("✓ 已添加 email_notification 列");
    }
  } catch (e: unknown) {
    console.error("添加 email_notification 列失败:", (e as Error).message);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'webhook_notification'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN webhook_notification TINYINT(1) DEFAULT 0 AFTER email_notification"
      );
      console.log("✓ 已添加 webhook_notification 列");
    }
  } catch (e: unknown) {
    console.error("添加 webhook_notification 列失败:", (e as Error).message);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'expected_status'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN expected_status INT DEFAULT 200 AFTER retries"
      );
      console.log("✓ 已添加 expected_status 列");
    }
  } catch (e: unknown) {
    console.error("添加 expected_status 列失败:", (e as Error).message);
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
      console.log(`✓ 已添加 group_id 列（位置：${afterColumn} 之后）`);
    } else {
      console.log("✓ group_id 列已存在");
    }
  } catch (e: unknown) {
    const err = e as Error;
    console.error("添加 group_id 列失败:", err.message);
    if (err.message?.includes("Duplicate column name")) {
      console.log("  (列已存在，忽略此错误)");
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
      console.log("✓ 已添加 monitor_groups.sort_order 列");
    } else {
      console.log("✓ monitor_groups.sort_order 列已存在");
    }
  } catch (e: unknown) {
    console.error("添加 monitor_groups.sort_order 列失败:", (e as Error).message);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'is_public'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN is_public TINYINT(1) DEFAULT 0 AFTER enabled"
      );
      console.log("✓ 已添加 monitors.is_public 列");
    } else {
      console.log("✓ monitors.is_public 列已存在");
    }
  } catch (e: unknown) {
    console.error("添加 monitors.is_public 列失败:", (e as Error).message);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'auth_username'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN auth_username VARCHAR(255) DEFAULT NULL AFTER is_public"
      );
      console.log("✓ 已添加 auth_username 列");
    } else {
      console.log("✓ monitors.auth_username 列已存在");
    }
  } catch (e: unknown) {
    console.error("添加 monitors.auth_username 列失败:", (e as Error).message);
  }

  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'auth_password'"
    );
    if (Array.isArray(columns) && columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN auth_password VARCHAR(255) DEFAULT NULL AFTER auth_username"
      );
      console.log("✓ 已添加 auth_password 列");
    } else {
      console.log("✓ monitors.auth_password 列已存在");
    }
  } catch (e: unknown) {
    console.error("添加 monitors.auth_password 列失败:", (e as Error).message);
  }

  try {
    const [tables] = await pool.execute("SHOW TABLES LIKE 'monitor_groups'");
    if (Array.isArray(tables) && tables.length === 0) {
      console.log("⚠ monitor_groups 表不存在，但应该已创建");
    } else {
      console.log("✓ monitor_groups 表已存在");
    }
  } catch (e: unknown) {
    console.error("检查 monitor_groups 表失败:", (e as Error).message);
  }

  console.log("数据表初始化完成");
}
