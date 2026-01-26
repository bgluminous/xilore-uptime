const mysql = require("mysql2/promise");

async function connectDatabase(config) {
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

  // 验证连接可用
  const conn = await pool.getConnection();
  conn.release();

  return pool;
}

async function initializeTables(pool) {
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      email VARCHAR(100),
      role ENUM('admin', 'user') DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  const createGroupsTable = `
    CREATE TABLE IF NOT EXISTS monitor_groups (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      description VARCHAR(255),
      sort_order INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  const createMonitorsTable = `
    CREATE TABLE IF NOT EXISTS monitors (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      type ENUM('http', 'tcp', 'ping') NOT NULL,
      target VARCHAR(255) NOT NULL,
      port INT,
      interval_seconds INT DEFAULT 60,
      timeout_seconds INT DEFAULT 10,
      retries INT DEFAULT 0,
      expected_status INT DEFAULT 200,
      group_id INT DEFAULT NULL,
      status ENUM('up', 'down', 'unknown') DEFAULT 'unknown',
      last_check TIMESTAMP NULL,
      last_response_time INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      enabled TINYINT(1) DEFAULT 1,
      is_public TINYINT(1) DEFAULT 0
    )
  `;

  const createHistoryTable = `
    CREATE TABLE IF NOT EXISTS check_history (
      id INT AUTO_INCREMENT PRIMARY KEY,
      monitor_id INT NOT NULL,
      status ENUM('up', 'down', 'warning') NOT NULL,
      response_time INT,
      message VARCHAR(255),
      checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_monitor (monitor_id),
      INDEX idx_time (checked_at),
      FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
    )
  `;

  // 如果表已存在，尝试添加warning状态（忽略错误，可能已经存在）
  const alterHistoryTable = `
    ALTER TABLE check_history
    MODIFY COLUMN status ENUM('up', 'down', 'warning') NOT NULL
  `;

  const createSettingsTable = `
    CREATE TABLE IF NOT EXISTS settings (
      id INT AUTO_INCREMENT PRIMARY KEY,
      key_name VARCHAR(100) NOT NULL UNIQUE,
      value TEXT,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `;

  await pool.execute(createUsersTable);
  await pool.execute(createGroupsTable);
  await pool.execute(createMonitorsTable);
  await pool.execute(createHistoryTable);
  await pool.execute(createSettingsTable);

  // 更新check_history表结构，添加warning状态
  try {
    await pool.execute(alterHistoryTable);
    console.log("✓ check_history表结构已更新，添加warning状态");
  } catch (e) {
    // 如果修改失败（可能是状态已存在），忽略错误
    if (
      e.message &&
      !e.message.includes("Duplicate") &&
      !e.message.includes("doesn't exist")
    ) {
      console.error("更新check_history表结构失败:", e.message);
    }
  }

  // 数据库迁移：如果旧表存在 timeout_ms 列，则迁移到 timeout_seconds
  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'timeout_ms'"
    );
    if (columns.length > 0) {
      await pool.execute(
        "ALTER TABLE monitors CHANGE timeout_ms timeout_seconds INT DEFAULT 10"
      );
      await pool.execute(
        "UPDATE monitors SET timeout_seconds = CEIL(timeout_seconds / 1000)"
      );
    }
  } catch (e) {
    // 忽略迁移错误
  }

  // 添加 retries 列（如果不存在）
  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'retries'"
    );
    if (columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN retries INT DEFAULT 0 AFTER timeout_seconds"
      );
      console.log("✓ 已添加 retries 列");
    }
  } catch (e) {
    // 忽略迁移错误
  }

  // 添加 email_notification 列（如果不存在）
  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'email_notification'"
    );
    if (columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN email_notification TINYINT(1) DEFAULT 0 AFTER is_public"
      );
      console.log("✓ 已添加 email_notification 列");
    }
  } catch (e) {
    console.error("添加 email_notification 列失败:", e.message);
  }

  // 添加 webhook_notification 列（如果不存在）
  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'webhook_notification'"
    );
    if (columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN webhook_notification TINYINT(1) DEFAULT 0 AFTER email_notification"
      );
      console.log("✓ 已添加 webhook_notification 列");
    }
  } catch (e) {
    console.error("添加 webhook_notification 列失败:", e.message);
  }

  // 添加 expected_status 列（如果不存在）
  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'expected_status'"
    );
    if (columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN expected_status INT DEFAULT 200 AFTER retries"
      );
      console.log("✓ 已添加 expected_status 列");
    }
  } catch (e) {
    console.error("添加 expected_status 列失败:", e.message);
  }

  // 添加 group_id 列（如果不存在）
  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'group_id'"
    );
    if (columns.length === 0) {
      // 先检查 expected_status 列的位置
      const [allColumns] = await pool.execute("SHOW COLUMNS FROM monitors");
      let afterColumn = "expected_status";

      // 如果 expected_status 不存在，检查 retries
      const hasExpectedStatus = allColumns.some(
        (col) => col.Field === "expected_status"
      );
      const hasRetries = allColumns.some((col) => col.Field === "retries");

      if (!hasExpectedStatus) {
        if (hasRetries) {
          afterColumn = "retries";
        } else {
          afterColumn = "timeout_seconds";
        }
      }

      // AFTER 子句不能参数化，所以需要验证列名
      const validColumns = ["expected_status", "retries", "timeout_seconds"];
      if (!validColumns.includes(afterColumn)) {
        afterColumn = "timeout_seconds";
      }

      await pool.execute(
        `ALTER TABLE monitors ADD COLUMN group_id INT DEFAULT NULL AFTER ${afterColumn}`
      );
      console.log(`✓ 已添加 group_id 列（位置：${afterColumn} 之后）`);
    } else {
      console.log("✓ group_id 列已存在");
    }
  } catch (e) {
    console.error("添加 group_id 列失败:", e.message);
    if (e.message && e.message.includes("Duplicate column name")) {
      console.log("  (列已存在，忽略此错误)");
    }
  }

  // 添加 monitor_groups.sort_order 列（如果不存在）
  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitor_groups LIKE 'sort_order'"
    );
    if (columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitor_groups ADD COLUMN sort_order INT DEFAULT 0 AFTER description"
      );
      console.log("✓ 已添加 monitor_groups.sort_order 列");
    } else {
      console.log("✓ monitor_groups.sort_order 列已存在");
    }
  } catch (e) {
    console.error("添加 monitor_groups.sort_order 列失败:", e.message);
  }

  // 添加 monitors.is_public 列（如果不存在）
  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'is_public'"
    );
    if (columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN is_public TINYINT(1) DEFAULT 0 AFTER enabled"
      );
      console.log("✓ 已添加 monitors.is_public 列");
    } else {
      console.log("✓ monitors.is_public 列已存在");
    }
  } catch (e) {
    console.error("添加 monitors.is_public 列失败:", e.message);
  }

  // 添加 auth_username 列（如果不存在）
  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'auth_username'"
    );
    if (columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN auth_username VARCHAR(255) DEFAULT NULL AFTER is_public"
      );
      console.log("✓ 已添加 auth_username 列");
    } else {
      console.log("✓ monitors.auth_username 列已存在");
    }
  } catch (e) {
    console.error("添加 monitors.auth_username 列失败:", e.message);
  }

  // 添加 auth_password 列（如果不存在）
  try {
    const [columns] = await pool.execute(
      "SHOW COLUMNS FROM monitors LIKE 'auth_password'"
    );
    if (columns.length === 0) {
      await pool.execute(
        "ALTER TABLE monitors ADD COLUMN auth_password VARCHAR(255) DEFAULT NULL AFTER auth_username"
      );
      console.log("✓ 已添加 auth_password 列");
    } else {
      console.log("✓ monitors.auth_password 列已存在");
    }
  } catch (e) {
    console.error("添加 monitors.auth_password 列失败:", e.message);
  }

  // 验证 monitor_groups 表是否存在
  try {
    const [tables] = await pool.execute("SHOW TABLES LIKE 'monitor_groups'");
    if (tables.length === 0) {
      console.log("⚠ monitor_groups 表不存在，但应该已创建");
    } else {
      console.log("✓ monitor_groups 表已存在");
    }
  } catch (e) {
    console.error("检查 monitor_groups 表失败:", e.message);
  }

  console.log("数据表初始化完成");
}

module.exports = {
  connectDatabase,
  initializeTables,
};

