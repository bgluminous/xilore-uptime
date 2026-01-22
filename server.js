const express = require('express');
const path = require('path');
const fs = require('fs');
const net = require('net');
const { exec } = require('child_process');
const http = require('http');
const https = require('https');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const CONFIG_PATH = path.join(__dirname, 'config.json');
const JWT_SECRET = process.env.JWT_SECRET || 'uptimebot-secret-key-change-in-production';

let pool = null;
let config = null;

// ============ 日志工具 ============
function log(level, message, data = null) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
  
  if (data) {
    console.log(logMessage, data);
  } else {
    console.log(logMessage);
  }
}

function logRequest(req, res, next) {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const statusColor = res.statusCode >= 400 ? 'ERROR' : res.statusCode >= 300 ? 'WARN' : 'INFO';
    log(statusColor, `${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`, {
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent')
    });
  });
  
  next();
}

// ============ 中间件 ============
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(logRequest);

// 在所有路由之前应用初始化检查中间件
app.use(initCheckMiddleware);

// ============ 配置管理 ============
function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
      log('INFO', '配置文件加载成功');
      return true;
    } else {
      log('INFO', '配置文件不存在，等待初始化');
    }
  } catch (e) {
    log('ERROR', '加载配置失败', { error: e.message });
  }
  return false;
}

function saveConfig(newConfig) {
  config = newConfig;
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
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
      await connectDatabase();
    } catch (e) {
      log('WARN', '数据库连接失败，系统未初始化', { error: e.message });
      return false;
    }
  }
  
  // 检查数据库中是否有管理员用户
  try {
    const [rows] = await pool.execute('SELECT COUNT(*) as count FROM users WHERE role = ?', ['admin']);
    const adminCount = rows[0].count;
    return adminCount > 0;
  } catch (e) {
    log('WARN', '检查初始化状态失败', { error: e.message });
    return false;
  }
}

// ============ 数据库连接 ============
async function connectDatabase() {
  if (!config || !config.database) {
    log('ERROR', '数据库配置不存在');
    throw new Error('数据库配置不存在');
  }
  
  pool = mysql.createPool({
    host: config.database.host,
    port: config.database.port || 3306,
    user: config.database.user,
    password: config.database.password,
    database: config.database.name,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });
  
  const conn = await pool.getConnection();
  conn.release();
  log('INFO', '数据库连接成功', { host: config.database.host, database: config.database.name });
}

async function initializeTables() {
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
    console.log('✓ check_history表结构已更新，添加warning状态');
  } catch (e) {
    // 如果修改失败（可能是状态已存在），忽略错误
    if (e.message && !e.message.includes('Duplicate') && !e.message.includes("doesn't exist")) {
      console.error('更新check_history表结构失败:', e.message);
    }
  }
  
  // 数据库迁移：如果旧表存在 timeout_ms 列，则迁移到 timeout_seconds
  try {
    const [columns] = await pool.execute(`SHOW COLUMNS FROM monitors LIKE 'timeout_ms'`);
    if (columns.length > 0) {
      await pool.execute(`ALTER TABLE monitors CHANGE timeout_ms timeout_seconds INT DEFAULT 10`);
      await pool.execute(`UPDATE monitors SET timeout_seconds = CEIL(timeout_seconds / 1000)`);
    }
  } catch (e) {
    // 忽略迁移错误
  }
  
  // 添加 retries 列（如果不存在）
  try {
    const [columns] = await pool.execute(`SHOW COLUMNS FROM monitors LIKE 'retries'`);
    if (columns.length === 0) {
      await pool.execute(`ALTER TABLE monitors ADD COLUMN retries INT DEFAULT 0 AFTER timeout_seconds`);
      console.log('✓ 已添加 retries 列');
    }
  } catch (e) {
    console.error('添加 retries 列失败:', e.message);
  }
  
  // 添加 expected_status 列（如果不存在）
  try {
    const [columns] = await pool.execute(`SHOW COLUMNS FROM monitors LIKE 'expected_status'`);
    if (columns.length === 0) {
      await pool.execute(`ALTER TABLE monitors ADD COLUMN expected_status INT DEFAULT 200 AFTER retries`);
      console.log('✓ 已添加 expected_status 列');
    }
  } catch (e) {
    console.error('添加 expected_status 列失败:', e.message);
  }
  
  // 添加 group_id 列（如果不存在）
  try {
    const [columns] = await pool.execute(`SHOW COLUMNS FROM monitors LIKE 'group_id'`);
    if (columns.length === 0) {
      // 先检查 expected_status 列的位置
      const [allColumns] = await pool.execute(`SHOW COLUMNS FROM monitors`);
      let afterColumn = 'expected_status';
      
      // 如果 expected_status 不存在，检查 retries
      const hasExpectedStatus = allColumns.some(col => col.Field === 'expected_status');
      const hasRetries = allColumns.some(col => col.Field === 'retries');
      
      if (!hasExpectedStatus) {
        if (hasRetries) {
          afterColumn = 'retries';
        } else {
          afterColumn = 'timeout_seconds';
        }
      }
      
      // 使用参数化查询避免 SQL 注入，但 AFTER 子句不能参数化，所以需要验证列名
      const validColumns = ['expected_status', 'retries', 'timeout_seconds'];
      if (!validColumns.includes(afterColumn)) {
        afterColumn = 'timeout_seconds';
      }
      
      await pool.execute(`ALTER TABLE monitors ADD COLUMN group_id INT DEFAULT NULL AFTER ${afterColumn}`);
      console.log(`✓ 已添加 group_id 列（位置：${afterColumn} 之后）`);
    } else {
      console.log('✓ group_id 列已存在');
    }
  } catch (e) {
    console.error('添加 group_id 列失败:', e.message);
    // 如果是因为列已存在而失败，这是正常的
    if (e.message.includes('Duplicate column name')) {
      console.log('  (列已存在，忽略此错误)');
    }
  }

  // 添加 monitor_groups.sort_order 列（如果不存在）
  try {
    const [columns] = await pool.execute(`SHOW COLUMNS FROM monitor_groups LIKE 'sort_order'`);
    if (columns.length === 0) {
      await pool.execute(`ALTER TABLE monitor_groups ADD COLUMN sort_order INT DEFAULT 0 AFTER description`);
      console.log('✓ 已添加 monitor_groups.sort_order 列');
    } else {
      console.log('✓ monitor_groups.sort_order 列已存在');
    }
  } catch (e) {
    console.error('添加 monitor_groups.sort_order 列失败:', e.message);
  }


  // 添加 monitors.is_public 列（如果不存在）
  try {
    const [columns] = await pool.execute(`SHOW COLUMNS FROM monitors LIKE 'is_public'`);
    if (columns.length === 0) {
      await pool.execute(`ALTER TABLE monitors ADD COLUMN is_public TINYINT(1) DEFAULT 0 AFTER enabled`);
      console.log('✓ 已添加 monitors.is_public 列');
    } else {
      console.log('✓ monitors.is_public 列已存在');
    }
  } catch (e) {
    console.error('添加 monitors.is_public 列失败:', e.message);
  }
  
  // 添加 auth_username 列（如果不存在）
  try {
    const [columns] = await pool.execute(`SHOW COLUMNS FROM monitors LIKE 'auth_username'`);
    if (columns.length === 0) {
      await pool.execute(`ALTER TABLE monitors ADD COLUMN auth_username VARCHAR(255) DEFAULT NULL AFTER is_public`);
      console.log('✓ 已添加 auth_username 列');
    } else {
      console.log('✓ monitors.auth_username 列已存在');
    }
  } catch (e) {
    console.error('添加 monitors.auth_username 列失败:', e.message);
  }
  
  // 添加 auth_password 列（如果不存在）
  try {
    const [columns] = await pool.execute(`SHOW COLUMNS FROM monitors LIKE 'auth_password'`);
    if (columns.length === 0) {
      await pool.execute(`ALTER TABLE monitors ADD COLUMN auth_password VARCHAR(255) DEFAULT NULL AFTER auth_username`);
      console.log('✓ 已添加 auth_password 列');
    } else {
      console.log('✓ monitors.auth_password 列已存在');
    }
  } catch (e) {
    console.error('添加 monitors.auth_password 列失败:', e.message);
  }
  
  // 验证 monitor_groups 表是否存在
  try {
    const [tables] = await pool.execute(`SHOW TABLES LIKE 'monitor_groups'`);
    if (tables.length === 0) {
      console.log('⚠ monitor_groups 表不存在，但应该已创建');
    } else {
      console.log('✓ monitor_groups 表已存在');
    }
  } catch (e) {
    console.error('检查 monitor_groups 表失败:', e.message);
  }
  
  console.log('数据表初始化完成');
}

// ============ 初始化检查中间件 ============
async function initCheckMiddleware(req, res, next) {
  // 允许访问初始化相关的路由和公开API（不需要初始化）
  const allowedPaths = [
    '/setup',
    '/api/install',
    '/api/public',
    '/api/auth/login',
    '/api/auth/logout'
  ];
  
  // 检查是否是允许的路径
  let isAllowed = allowedPaths.some(allowedPath => {
    // 对于精确路径匹配
    if (req.path === allowedPath) {
      return true;
    }
    // 对于前缀匹配
    if (req.path.startsWith(allowedPath)) {
      return true;
    }
    return false;
  });
  
  // 对于静态文件，允许访问（在允许的路径检查之后）
  if (!isAllowed && req.path.match(/\.(css|js|html|svg|png|jpg|jpeg|gif|ico|woff|woff2|ttf|eot)$/i)) {
    isAllowed = true;
  }
  
  if (isAllowed) {
    return next();
  }
  
  // 检查系统是否已初始化
  try {
    const initialized = await isInitialized();
    
    if (!initialized) {
      // 如果未初始化，所有路由（包括根路径）都重定向到 /setup
      // 如果是 API 请求，返回 JSON 错误
      if (req.path.startsWith('/api')) {
        return res.status(400).json({ error: '系统未初始化，请访问 /setup 进行初始化' });
      }
      
      // 如果是页面请求（包括根路径 /），重定向到 /setup
      return res.redirect('/setup');
    }
    
    // 系统已初始化，允许继续访问
    next();
  } catch (error) {
    // 如果检查初始化状态失败，也视为未初始化
    log('WARN', '检查初始化状态失败', { error: error.message, path: req.path });
    
    if (req.path.startsWith('/api')) {
      return res.status(400).json({ error: '系统未初始化，请访问 /setup 进行初始化' });
    }
    
    return res.redirect('/setup');
  }
}

// ============ 认证中间件 ============
function authMiddleware(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    log('WARN', '未授权访问', { path: req.path, method: req.method });
    return res.status(401).json({ error: '未登录' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    log('WARN', 'Token 验证失败', { path: req.path, error: e.message });
    return res.status(401).json({ error: '登录已过期' });
  }
}

// ============ 安装向导路由 ============
app.get('/api/install/status', async (req, res) => {
  const installed = isInstalled();
  const initialized = installed ? await isInitialized() : false;
  res.json({ installed, initialized });
});

app.post('/api/install/test-db', async (req, res) => {
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
    log('WARN', '检查初始化状态失败', { error: error.message });
  }
  
  const { host, port, user, password, name } = req.body;
  
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
      const [tables] = await conn.query(`SHOW TABLES LIKE 'users'`);
      if (tables.length > 0) {
        initialized = true;
        // 检查是否存在管理员账户
        const [admins] = await conn.query(`SELECT COUNT(*) as count FROM users WHERE role = 'admin'`);
        adminCount = admins[0].count;
        hasAdmin = adminCount > 0;
      }
    } catch (e) {
      // 数据库可能是空的，忽略错误
    }
    
    conn.release();
    await testPool.end();
    
    res.json({ 
      success: true, 
      message: hasAdmin ? `数据库已初始化，发现 ${adminCount} 个管理员账户` : '数据库连接成功',
      initialized,
      hasAdmin,
      adminCount
    });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/api/install/complete', async (req, res) => {
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
    log('WARN', '检查初始化状态失败', { error: error.message });
  }
  
  const { database, admin, skipAdmin } = req.body;
  
  if (!database) {
    return res.status(400).json({ error: '缺少数据库配置' });
  }
  
  // 如果不跳过管理员创建，则验证管理员信息
  if (!skipAdmin) {
    if (!admin || !admin.username || !admin.password) {
      return res.status(400).json({ error: '请填写管理员账户信息' });
    }
    
    if (admin.password.length < 6) {
      return res.status(400).json({ error: '密码长度至少6位' });
    }
  }
  
  try {
    // 保存配置
    saveConfig({
      database: {
        host: database.host,
        port: database.port || 3306,
        user: database.user,
        password: database.password,
        name: database.name
      },
      installed: true,
      installedAt: new Date().toISOString()
    });
    
    // 连接数据库
    await connectDatabase();
    
    // 初始化表结构
    await initializeTables();
    
    // 如果需要创建管理员账户
    if (!skipAdmin && admin) {
      const hashedPassword = await bcrypt.hash(admin.password, 10);
      await pool.execute(
        'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
        [admin.username, hashedPassword, admin.email || null, 'admin']
      );
    }
    
    // 启动监控任务
    initializeChecks();
    
    res.json({ success: true, message: '安装完成' });
  } catch (e) {
    // 回滚配置
    if (fs.existsSync(CONFIG_PATH)) {
      fs.unlinkSync(CONFIG_PATH);
    }
    config = null;
    pool = null;
    
    res.status(500).json({ error: e.message });
  }
});

// ============ 认证路由 ============
app.post('/api/auth/login', async (req, res) => {
  if (!isInstalled()) {
    log('WARN', '登录尝试 - 系统未安装');
    return res.status(400).json({ error: '系统未安装' });
  }
  
  const { username, password } = req.body;
  
  if (!username || !password) {
    log('WARN', '登录尝试 - 缺少用户名或密码');
    return res.status(400).json({ error: '请输入用户名和密码' });
  }
  
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    
    if (rows.length === 0) {
      log('WARN', '登录失败 - 用户不存在', { username });
      return res.status(401).json({ error: '用户名或密码错误' });
    }
    
    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      log('WARN', '登录失败 - 密码错误', { username });
      return res.status(401).json({ error: '用户名或密码错误' });
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'lax'
    });
    
    log('INFO', '用户登录成功', { username: user.username, userId: user.id, role: user.role });
    
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } catch (e) {
    log('ERROR', '登录过程出错', { username, error: e.message });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// ============ 监控检测函数 ============
async function checkHttp(target, timeoutSeconds, expectedStatus = 200, authUsername = null, authPassword = null) {
  const timeout = timeoutSeconds * 1000;
  const startTime = Date.now();
  const initialUrl = target.startsWith('http') ? target : `https://${target}`;
  
  // 支持跟随重定向的 HTTP 请求
  const makeRequest = (url, redirectCount = 0) => {
    return new Promise((resolve) => {
      if (redirectCount > 5) {
        resolve({
          status: 'down',
          responseTime: null,
          message: '重定向次数过多'
        });
        return;
      }
      
      let parsedUrl;
      try {
        parsedUrl = new URL(url);
      } catch (err) {
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
      
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        timeout,
        headers
      };
      
      const req = protocol.request(options, (res) => {
        const responseTime = Date.now() - startTime;
        
        // 处理重定向 (301, 302, 303, 307, 308)
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          res.destroy();
          // 构建重定向 URL
          let redirectUrl = res.headers.location;
          if (!redirectUrl.startsWith('http')) {
            redirectUrl = `${parsedUrl.protocol}//${parsedUrl.host}${redirectUrl}`;
          }
          // 递归跟随重定向
          resolve(makeRequest(redirectUrl, redirectCount + 1));
          return;
        }
        
        // 检查期望状态码
        // expectedStatus 为 0 表示接受任何 2xx 状态码
        let success;
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
      
      req.on('error', (err) => {
        // 网络错误（DNS解析失败、连接错误等）不记录响应时间
        resolve({
          status: 'down',
          responseTime: null,
          message: err.message
        });
      });
      
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

async function checkTcp(target, port, timeoutSeconds) {
  const timeout = timeoutSeconds * 1000;
  return new Promise((resolve) => {
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
    
    socket.on('error', (err) => {
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

async function checkPing(target, timeoutSeconds) {
  const timeout = timeoutSeconds * 1000;
  return new Promise((resolve) => {
    const startTime = Date.now();
    const isWin = process.platform === 'win32';
    const cmd = isWin 
      ? `ping -n 1 -w ${timeout} ${target}`
      : `ping -c 1 -W ${timeoutSeconds} ${target}`;
    
    exec(cmd, { timeout: timeout + 1000 }, (error, stdout) => {
      // 如果超时或错误，不记录响应时间
      if (error) {
        // 检查是否是超时错误
        const isTimeout = error.code === 'ETIMEDOUT' || error.signal === 'SIGTERM' || error.message.includes('timeout');
        // 主机不可达、网络错误等都不记录响应时间
        resolve({
          status: 'down',
          responseTime: null,
          message: isTimeout ? 'Ping 超时' : '主机不可达'
        });
        return;
      }
      
      // 从 ping 输出中解析响应时间
      let pingTime = Date.now() - startTime; // 默认使用总耗时
      const timeMatch = stdout.match(/[=<](\d+)(?:\.\d+)?(?:\s*)?ms/i);
      if (timeMatch) {
        pingTime = parseInt(timeMatch[1]);
      }
      
      resolve({
        status: 'up',
        responseTime: pingTime,
        message: 'Ping 成功'
      });
    });
  });
}

// 单次检测
async function singleCheck(monitor) {
  const timeout = monitor.timeout_seconds || 10;
  const expectedStatus = monitor.expected_status || 200;
  
  switch (monitor.type) {
    case 'http':
      return await checkHttp(monitor.target, timeout, expectedStatus, monitor.auth_username, monitor.auth_password);
    case 'tcp':
      return await checkTcp(monitor.target, monitor.port, timeout);
    case 'ping':
      return await checkPing(monitor.target, timeout);
    default:
      return { status: 'unknown', responseTime: 0, message: '未知类型' };
  }
}

// 带重试的检测
async function performCheck(monitor) {
  const maxRetries = Math.min(monitor.retries || 0, 3);
  let result;
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
  
  // 更新监控状态（超时时 responseTime 为 null）
  // 注意：监控状态仍然使用原始的up/down，不使用warning
  await pool.execute(
    'UPDATE monitors SET status = ?, last_check = NOW(), last_response_time = ? WHERE id = ?',
    [result.status, result.responseTime || null, monitor.id]
  );
  
  // 记录历史（超时时 responseTime 为 null）
  // 如果重试后才成功，历史记录中使用warning状态
  await pool.execute(
    'INSERT INTO check_history (monitor_id, status, response_time, message) VALUES (?, ?, ?, ?)',
    [monitor.id, historyStatus, result.responseTime || null, result.message]
  );
  
  // 清理旧历史记录（保留最近7天）
  const [cleanupResult] = await pool.execute(
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
app.get('/api/groups', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM monitor_groups ORDER BY sort_order ASC, id ASC');
    res.json(rows);
  } catch (e) {
    log('ERROR', 'API 错误', { path: req.path, method: req.method, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/groups', authMiddleware, async (req, res) => {
  const { name, description } = req.body;
  
  if (!name) {
    log('WARN', '创建分组失败 - 名称为空', { user: req.user?.username });
    return res.status(400).json({ error: '分组名称不能为空' });
  }
  
  try {
    // 检查名称是否已存在
    const [existing] = await pool.execute(
      'SELECT id FROM monitor_groups WHERE name = ?',
      [name]
    );
    
    if (existing.length > 0) {
      log('WARN', '创建分组失败 - 名称重复', { name, user: req.user?.username });
      return res.status(400).json({ error: '分组名称已存在' });
    }
    
    const [maxRows] = await pool.execute('SELECT COALESCE(MAX(sort_order), 0) AS max_order FROM monitor_groups');
    const nextOrder = (maxRows[0]?.max_order || 0) + 1;
    const [result] = await pool.execute(
      'INSERT INTO monitor_groups (name, description, sort_order) VALUES (?, ?, ?)',
      [name, description || null, nextOrder]
    );
    log('INFO', '创建分组成功', { groupId: result.insertId, name, user: req.user?.username });
    res.json({ id: result.insertId, name, description, sort_order: nextOrder });
  } catch (e) {
    log('ERROR', '创建分组失败', { name, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/groups/:id', authMiddleware, async (req, res) => {
  const { name, description, sort_order } = req.body;
  const id = req.params.id;
  
  try {
    // 如果提供了名称，检查是否与其他分组重复（排除当前分组）
    if (name !== undefined && name !== null) {
      const [existing] = await pool.execute(
        'SELECT id FROM monitor_groups WHERE name = ? AND id != ?',
        [name, id]
      );
      
      if (existing.length > 0) {
        log('WARN', '更新分组失败 - 名称重复', { groupId: id, name, user: req.user?.username });
        return res.status(400).json({ error: '分组名称已存在' });
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
      const [group] = await pool.execute('SELECT * FROM monitor_groups WHERE id = ?', [id]);
      return res.json(group[0]);
    }
    
    values.push(id);
    await pool.execute(
      `UPDATE monitor_groups SET ${updates.join(', ')} WHERE id = ?`,
      values
    );
    
    // 返回更新后的分组信息
    const [updated] = await pool.execute('SELECT * FROM monitor_groups WHERE id = ?', [id]);
    
    log('INFO', '更新分组成功', { groupId: id, name, sort_order, user: req.user?.username });
    res.json(updated[0]);
  } catch (e) {
    log('ERROR', '更新分组失败', { groupId: id, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/groups/:id', authMiddleware, async (req, res) => {
  const id = req.params.id;
  
  try {
    // 将该分组下的监控移到"未分组"
    const [updateResult] = await pool.execute('UPDATE monitors SET group_id = NULL WHERE group_id = ?', [id]);
    await pool.execute('DELETE FROM monitor_groups WHERE id = ?', [id]);
    log('INFO', '删除分组成功', { groupId: id, affectedMonitors: updateResult.affectedRows, user: req.user?.username });
    res.json({ success: true });
  } catch (e) {
    log('ERROR', '删除分组失败', { groupId: id, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

// ============ 监控 API ============
app.get('/api/monitors', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM monitors ORDER BY group_id ASC, created_at DESC');
    
    // 为每个监控添加最近24小时的状态条数据
    const monitorsWithStatusBar = await Promise.all(rows.map(async (monitor) => {
      // 将24小时分成24个时间段（每个60分钟）
      const statusBar = [];
      const now = new Date();
      
      for (let i = 23; i >= 0; i--) {
        const startTime = new Date(now.getTime() - (i + 1) * 60 * 60 * 1000);
        const endTime = new Date(now.getTime() - i * 60 * 60 * 1000);
        
        // 查询该时间段内的所有检测记录（按时间升序，用于前端细分时间段）
        const [historyRows] = await pool.execute(
          `SELECT status, checked_at, message FROM check_history 
           WHERE monitor_id = ? AND checked_at >= ? AND checked_at < ?
           ORDER BY checked_at ASC`,
          [monitor.id, startTime, endTime]
        );
        
        if (historyRows.length === 0) {
          // 没有数据，显示灰色
          statusBar.push({ 
            status: null, 
            startTime: startTime.toISOString(), 
            endTime: endTime.toISOString(),
            totalChecks: 0,
            upChecks: 0,
            downChecks: 0,
            warningChecks: 0,
            uptime: null
          });
        } else {
          // 统计该时间段内的检测情况
          let totalChecks = historyRows.length;
          let upChecks = 0;
          let downChecks = 0;
          let warningChecks = 0;
          let latestCheckTime = null;
          let latestMessage = null;
          
          // 优先显示down，然后warning，最后up
          let finalStatus = null;
          
          for (const row of historyRows) {
            if (!latestCheckTime) {
              latestCheckTime = row.checked_at;
              latestMessage = row.message;
            }
            
            // 统计各状态数量
            if (row.status === 'up') {
              upChecks++;
              if (!finalStatus) {
                finalStatus = 'up';
              }
            } else if (row.status === 'down') {
              downChecks++;
              finalStatus = 'down';
              // 找到down状态时，使用该记录的message
              latestCheckTime = row.checked_at;
              latestMessage = row.message;
            } else if (row.status === 'warning') {
              warningChecks++;
              if (finalStatus !== 'down') {
                finalStatus = 'warning';
                // 如果还没找到down，使用warning的message
                if (!latestMessage || finalStatus === 'warning') {
                  latestCheckTime = row.checked_at;
                  latestMessage = row.message;
                }
              }
            }
          }
          
          // 计算可用率（warning也算作可用）
          const uptime = totalChecks > 0 ? ((upChecks + warningChecks) / totalChecks) * 100 : null;
          
          // 将检测记录按时间排序，供前端细分时间段使用
          const checkRecords = historyRows.map(row => ({
            status: row.status,
            checked_at: row.checked_at,
            message: row.message
          }));
          
          statusBar.push({ 
            status: finalStatus || null, 
            startTime: startTime.toISOString(), 
            endTime: endTime.toISOString(), 
            checkTime: latestCheckTime ? new Date(latestCheckTime).toISOString() : null,
            message: latestMessage || null,
            totalChecks,
            upChecks,
            downChecks,
            warningChecks,
            uptime,
            checkRecords: checkRecords // 添加检测记录数组，供前端细分时间段
          });
        }
      }
      
      // 计算24小时可用率（warning也算作可用）
      const [uptimeRows] = await pool.execute(
        `SELECT 
          COUNT(*) as total_checks,
          SUM(CASE WHEN status = 'up' OR status = 'warning' THEN 1 ELSE 0 END) as up_checks
        FROM check_history
        WHERE monitor_id = ? 
          AND checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
        [monitor.id]
      );
      
      const uptimeData = uptimeRows[0] || { total_checks: 0, up_checks: 0 };
      const uptime_24h = uptimeData.total_checks > 0 
        ? (uptimeData.up_checks / uptimeData.total_checks) * 100 
        : null;
      
      return {
        ...monitor,
        uptime_24h,
        statusBar24h: statusBar
      };
    }));
    
    res.json(monitorsWithStatusBar);
  } catch (e) {
    log('ERROR', 'API 错误', { path: req.path, method: req.method, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/monitors/:id', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM monitors WHERE id = ?', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: '监控不存在' });
    }
    res.json(rows[0]);
  } catch (e) {
    log('ERROR', 'API 错误', { path: req.path, method: req.method, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/monitors', authMiddleware, async (req, res) => {
  const { name, type, target, port, interval_seconds, timeout_seconds, retries, expected_status, group_id, is_public, auth_username, auth_password } = req.body;
  
  if (!name || !type || !target) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  
  if (type === 'tcp' && !port) {
    return res.status(400).json({ error: 'TCP 检测需要指定端口' });
  }
  
  // 限制重试次数 0-3
  const validRetries = Math.max(0, Math.min(3, retries || 0));
  // 期望状态码，0 表示任意 2xx
  const validExpectedStatus = expected_status !== undefined ? parseInt(expected_status) : 200;
  // Basic Auth 字段（仅 HTTP 模式使用）
  const validAuthUsername = (type === 'http' && auth_username) ? auth_username.trim() : null;
  const validAuthPassword = (type === 'http' && auth_password) ? auth_password : null;
  
  try {
    const [result] = await pool.execute(
      'INSERT INTO monitors (name, type, target, port, interval_seconds, timeout_seconds, retries, expected_status, group_id, is_public, auth_username, auth_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [name, type, target, port || null, interval_seconds || 60, timeout_seconds || 10, validRetries, validExpectedStatus, group_id || null, is_public ? 1 : 0, validAuthUsername, validAuthPassword]
    );
    
    const [rows] = await pool.execute('SELECT * FROM monitors WHERE id = ?', [result.insertId]);
    startMonitorCheck(rows[0]);
    
    log('INFO', '创建监控成功', { 
      monitorId: result.insertId, 
      name, 
      type, 
      target, 
      groupId: group_id || null,
      user: req.user?.username 
    });
    
    res.status(201).json(rows[0]);
  } catch (e) {
    log('ERROR', '创建监控失败', { name, type, target, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/monitors/:id', authMiddleware, async (req, res) => {
  const { name, type, target, port, interval_seconds, timeout_seconds, retries, expected_status, group_id, enabled, is_public, auth_username, auth_password } = req.body;
  const id = req.params.id;
  
  // 确保所有参数都不是 undefined，统一转换为 null 或有效值
  // MySQL2 不允许 undefined，必须使用 null
  const safeValue = (val) => val === undefined ? null : val;
  const safeInt = (val) => val === undefined ? null : (val !== null ? parseInt(val) : null);
  const safeBool = (val) => val === undefined ? null : (val !== null ? Boolean(val) : null);
  
  // 限制重试次数 0-3
  const validRetries = retries !== undefined ? Math.max(0, Math.min(3, retries)) : null;
  // 期望状态码
  const validExpectedStatus = expected_status !== undefined ? parseInt(expected_status) : null;
  // group_id 可以为 null（未分组）
  const validGroupId = (group_id === undefined || group_id === '' || group_id === 0 || group_id === null) 
    ? null 
    : (typeof group_id === 'string' ? parseInt(group_id) : group_id);
  // Basic Auth 字段（仅 HTTP 模式使用）
  const validAuthUsername = (type === 'http' && auth_username !== undefined) 
    ? (auth_username ? auth_username.trim() : null) 
    : (type !== 'http' ? null : undefined); // 如果类型不是 http，设为 null；如果类型是 http 但未提供，保持 undefined
  const validAuthPassword = (type === 'http' && auth_password !== undefined) 
    ? (auth_password ? auth_password : null) 
    : (type !== 'http' ? null : undefined);
  
  try {
    const [existing] = await pool.execute('SELECT * FROM monitors WHERE id = ?', [id]);
    if (existing.length === 0) {
      return res.status(404).json({ error: '监控不存在' });
    }
    
    // 如果类型是 http 且 auth 字段未提供，保持原有值；如果提供了，使用新值
    const finalAuthUsername = validAuthUsername !== undefined ? validAuthUsername : existing[0].auth_username;
    const finalAuthPassword = validAuthPassword !== undefined ? validAuthPassword : existing[0].auth_password;
    
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
      validGroupId,
      safeBool(enabled),
      is_public !== undefined ? (is_public ? 1 : 0) : null,
      finalAuthUsername,
      finalAuthPassword,
      id
    ];
    
    await pool.execute(
      `UPDATE monitors SET 
        name = COALESCE(?, name),
        type = COALESCE(?, type),
        target = COALESCE(?, target),
        port = COALESCE(?, port),
        interval_seconds = COALESCE(?, interval_seconds),
        timeout_seconds = COALESCE(?, timeout_seconds),
        retries = COALESCE(?, retries),
        expected_status = COALESCE(?, expected_status),
        group_id = ?,
        enabled = COALESCE(?, enabled),
        is_public = COALESCE(?, is_public),
        auth_username = ?,
        auth_password = ?
        WHERE id = ?`,
      params
    );
    
    const [rows] = await pool.execute('SELECT * FROM monitors WHERE id = ?', [id]);
    startMonitorCheck(rows[0]);
    
    log('INFO', '更新监控成功', { 
      monitorId: id, 
      name: name || '未更改',
      type: type || '未更改',
      groupId: validGroupId,
      user: req.user?.username 
    });
    
    res.json(rows[0]);
  } catch (e) {
    log('ERROR', '更新监控失败', { monitorId: id, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/monitors/:id', authMiddleware, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    // 获取监控信息用于日志
    const [monitor] = await pool.execute('SELECT name, type, target FROM monitors WHERE id = ?', [id]);
    
    if (checkIntervals.has(id)) {
      clearInterval(checkIntervals.get(id));
      checkIntervals.delete(id);
      log('INFO', '停止监控任务', { monitorId: id });
    }
    
    await pool.execute('DELETE FROM monitors WHERE id = ?', [id]);
    
    log('INFO', '删除监控成功', { 
      monitorId: id, 
      name: monitor[0]?.name || '未知',
      type: monitor[0]?.type || '未知',
      user: req.user?.username 
    });
    
    res.json({ success: true });
  } catch (e) {
    log('ERROR', '删除监控失败', { monitorId: id, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/monitors/:id/check', authMiddleware, async (req, res) => {
  const id = req.params.id;
  try {
    const [rows] = await pool.execute('SELECT * FROM monitors WHERE id = ?', [id]);
    if (rows.length === 0) {
      log('WARN', '手动检测失败 - 监控不存在', { monitorId: id, user: req.user?.username });
      return res.status(404).json({ error: '监控不存在' });
    }
    
    log('INFO', '开始手动检测', { monitorId: id, name: rows[0].name, target: rows[0].target, user: req.user?.username });
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
    log('ERROR', '手动检测失败', { monitorId: id, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/monitors/:id/history', authMiddleware, async (req, res) => {
  const id = req.params.id;
  try {
    const [rows] = await pool.execute('SELECT * FROM monitors WHERE id = ?', [id]);
    if (rows.length === 0) {
      log('WARN', '清空历史失败 - 监控不存在', { monitorId: id, user: req.user?.username });
      return res.status(404).json({ error: '监控不存在' });
    }
    
    const [deleteResult] = await pool.execute('DELETE FROM check_history WHERE monitor_id = ?', [id]);
    log('INFO', '清空监控历史成功', { 
      monitorId: id, 
      name: rows[0].name, 
      deletedRecords: deleteResult.affectedRows,
      user: req.user?.username 
    });
    
    res.json({ success: true });
  } catch (e) {
    log('ERROR', '清空监控历史失败', { monitorId: id, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/monitors/:id/history/:historyId', authMiddleware, async (req, res) => {
  const monitorId = req.params.id;
  const historyId = req.params.historyId;
  try {
    // 验证监控是否存在
    const [monitorRows] = await pool.execute('SELECT * FROM monitors WHERE id = ?', [monitorId]);
    if (monitorRows.length === 0) {
      log('WARN', '删除历史记录失败 - 监控不存在', { monitorId, historyId, user: req.user?.username });
      return res.status(404).json({ error: '监控不存在' });
    }
    
    // 验证历史记录是否存在且属于该监控
    const [historyRows] = await pool.execute('SELECT * FROM check_history WHERE id = ? AND monitor_id = ?', [historyId, monitorId]);
    if (historyRows.length === 0) {
      log('WARN', '删除历史记录失败 - 记录不存在', { monitorId, historyId, user: req.user?.username });
      return res.status(404).json({ error: '历史记录不存在' });
    }
    
    // 删除历史记录
    await pool.execute('DELETE FROM check_history WHERE id = ? AND monitor_id = ?', [historyId, monitorId]);
    log('INFO', '删除历史记录成功', { 
      monitorId, 
      historyId,
      name: monitorRows[0].name, 
      user: req.user?.username 
    });
    
    res.json({ success: true });
  } catch (e) {
    log('ERROR', '删除历史记录失败', { monitorId, historyId, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

// 删除所有检测历史
app.delete('/api/history/all', authMiddleware, async (req, res) => {
  try {
    const [deleteResult] = await pool.execute('DELETE FROM check_history');
    log('INFO', '删除所有检测历史成功', { 
      deletedRecords: deleteResult.affectedRows,
      user: req.user?.username 
    });
    
    res.json({ success: true, deletedRecords: deleteResult.affectedRows });
  } catch (e) {
    log('ERROR', '删除所有检测历史失败', { error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/monitors/:id/history', authMiddleware, async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 100, 1), 1000);
  const range = req.query.range || '24h'; // 1h, 24h, 7d, 30d
  
  // 计算时间范围
  let hours = 24;
  switch (range) {
    case '1h': hours = 1; break;
    case '24h': hours = 24; break;
    case '7d': hours = 24 * 7; break;
    case '30d': hours = 24 * 30; break;
  }
  
  try {
    // 注意：MySQL 的 LIMIT 和 INTERVAL 不能直接用参数化，需要拼接（已确保是安全的整数值）
    const [rows] = await pool.execute(
      `SELECT * FROM check_history 
       WHERE monitor_id = ? AND checked_at >= DATE_SUB(NOW(), INTERVAL ${hours} HOUR)
       ORDER BY checked_at DESC LIMIT ${limit}`,
      [req.params.id]
    );
    
    // 计算统计信息（warning也算作可用）
    const [stats] = await pool.execute(
      `SELECT 
         COUNT(*) as total,
         SUM(CASE WHEN status = 'up' OR status = 'warning' THEN 1 ELSE 0 END) as up_count,
         AVG(response_time) as avg_response,
         MIN(response_time) as min_response,
         MAX(response_time) as max_response
       FROM check_history 
       WHERE monitor_id = ? AND checked_at >= DATE_SUB(NOW(), INTERVAL ${hours} HOUR)`,
      [req.params.id]
    );
    
    res.json({
      history: rows,
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
    log('ERROR', '获取历史记录失败', { monitorId: req.params.id, range, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

// ============ 设置 API ============
app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
    if (!pool) {
      return res.json({ publicPageTitle: '服务状态监控' });
    }
    
    try {
      const [rows] = await pool.execute(
        'SELECT value FROM settings WHERE key_name = ?',
        ['publicPageTitle']
      );
      
      const publicPageTitle = rows.length > 0 && rows[0].value 
        ? rows[0].value 
        : '服务状态监控';
      
      res.json({ publicPageTitle });
    } catch (dbError) {
      // 如果表不存在或其他数据库错误，返回默认值
      log('WARN', '获取设置失败，使用默认值', { error: dbError.message, user: req.user?.username });
      res.json({ publicPageTitle: '服务状态监控' });
    }
  } catch (e) {
    log('ERROR', '获取设置失败', { error: e.message, user: req.user?.username });
    res.json({ publicPageTitle: '服务状态监控' });
  }
});

app.put('/api/settings', authMiddleware, async (req, res) => {
  try {
    if (!pool) {
      return res.status(500).json({ error: '数据库未连接' });
    }
    
    const { publicPageTitle } = req.body;
    
    if (publicPageTitle !== undefined) {
      const value = publicPageTitle || '服务状态监控';
      
      // 使用 INSERT ... ON DUPLICATE KEY UPDATE 来插入或更新
      await pool.execute(
        `INSERT INTO settings (key_name, value) 
         VALUES (?, ?) 
         ON DUPLICATE KEY UPDATE value = ?, updated_at = CURRENT_TIMESTAMP`,
        ['publicPageTitle', value, value]
      );
      
      log('INFO', '更新设置成功', { publicPageTitle: value, user: req.user?.username });
    }
    
    // 返回更新后的设置
    const [rows] = await pool.execute(
      'SELECT value FROM settings WHERE key_name = ?',
      ['publicPageTitle']
    );
    
    const updatedTitle = rows.length > 0 && rows[0].value 
      ? rows[0].value 
      : '服务状态监控';
    
    res.json({ publicPageTitle: updatedTitle });
  } catch (e) {
    log('ERROR', '更新设置失败', { error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const [total] = await pool.execute('SELECT COUNT(*) as count FROM monitors');
    const [up] = await pool.execute("SELECT COUNT(*) as count FROM monitors WHERE status = 'up'");
    const [down] = await pool.execute("SELECT COUNT(*) as count FROM monitors WHERE status = 'down'");
    
    // 计算24小时平均可用率（warning也算作可用）
    const [uptimeRows] = await pool.execute(
      `SELECT 
        m.id,
        COUNT(*) as total_checks,
        SUM(CASE WHEN h.status = 'up' OR h.status = 'warning' THEN 1 ELSE 0 END) as up_checks
      FROM monitors m
      LEFT JOIN check_history h ON m.id = h.monitor_id 
        AND h.checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
      GROUP BY m.id`
    );
    
    let totalUptime = 0;
    let monitorCount = 0;
    
    uptimeRows.forEach(row => {
      if (row.total_checks > 0) {
        const uptime = (row.up_checks / row.total_checks) * 100;
        totalUptime += uptime;
        monitorCount++;
      }
    });
    
    const avgUptime = monitorCount > 0 ? (totalUptime / monitorCount) : 100;
    
    res.json({
      total: total[0].count,
      up: up[0].count,
      down: down[0].count,
      avgUptime24h: avgUptime
    });
  } catch (e) {
    log('ERROR', 'API 错误', { path: req.path, method: req.method, error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/check-all', authMiddleware, async (req, res) => {
  try {
    log('INFO', '开始批量检测所有监控', { user: req.user?.username });
    const [monitors] = await pool.execute('SELECT * FROM monitors WHERE enabled = 1');
    const results = await Promise.all(
      monitors.map(async (monitor) => {
        try {
          const result = await performCheck(monitor);
          return { id: monitor.id, name: monitor.name, ...result };
        } catch (e) {
          return { id: monitor.id, name: monitor.name, status: 'error', responseTime: 0, message: e.message };
        }
      })
    );
    
    log('INFO', '批量检测完成', { total: monitors.length, user: req.user?.username });
    res.json(results);
  } catch (e) {
    log('ERROR', '批量检测失败', { error: e.message, user: req.user?.username });
    res.status(500).json({ error: e.message });
  }
});

// ============ 定时检测任务 ============
const checkIntervals = new Map();

function startMonitorCheck(monitor) {
  if (checkIntervals.has(monitor.id)) {
    clearInterval(checkIntervals.get(monitor.id));
  }
  
  if (!monitor.enabled) return;
  
  const interval = setInterval(async () => {
    try {
      const [rows] = await pool.execute('SELECT * FROM monitors WHERE id = ?', [monitor.id]);
      if (rows.length > 0 && rows[0].enabled) {
        await performCheck(rows[0]);
      } else if (rows.length === 0 || !rows[0].enabled) {
        // 监控被删除或禁用，停止定时任务
        clearInterval(interval);
        checkIntervals.delete(monitor.id);
        log('INFO', '监控任务已停止', { monitorId: monitor.id, reason: rows.length === 0 ? '已删除' : '已禁用' });
      }
    } catch (e) {
      log('ERROR', '定时检测失败', { monitorId: monitor.id, error: e.message });
    }
  }, monitor.interval_seconds * 1000);
  
  checkIntervals.set(monitor.id, interval);
}

async function initializeChecks() {
  if (!pool) return;
  
  try {
    const [monitors] = await pool.execute('SELECT * FROM monitors WHERE enabled = 1');
    monitors.forEach(startMonitorCheck);
    log('INFO', '初始化监控任务', { count: monitors.length });
  } catch (e) {
    log('ERROR', '初始化监控任务失败', { error: e.message });
  }
}

setInterval(async () => {
  if (!pool) return;
  
  try {
    const [monitors] = await pool.execute('SELECT * FROM monitors WHERE enabled = 1');
    monitors.forEach(monitor => {
      if (!checkIntervals.has(monitor.id)) {
        startMonitorCheck(monitor);
      }
    });
  } catch (e) {}
}, 30000);

// ============ 公开 API（不需要认证）============
app.get('/api/public/title', async (req, res) => {
  try {
    if (!pool) {
      return res.json({ title: '服务状态监控' });
    }
    
    try {
      const [rows] = await pool.execute(
        'SELECT value FROM settings WHERE key_name = ?',
        ['publicPageTitle']
      );
      
      const title = rows.length > 0 && rows[0].value 
        ? rows[0].value 
        : '服务状态监控';
      
      res.json({ title });
    } catch (dbError) {
      // 如果表不存在或其他数据库错误，返回默认值
      log('WARN', '获取公开页面标题失败，使用默认值', { error: dbError.message });
      res.json({ title: '服务状态监控' });
    }
  } catch (e) {
    log('ERROR', '公开API错误', { path: req.path, method: req.method, error: e.message });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/public/groups', async (req, res) => {
  try {
    // 获取所有分组，但只返回那些有公开服务的分组
    const [rows] = await pool.execute(
      `SELECT DISTINCT g.* 
       FROM monitor_groups g
       INNER JOIN monitors m ON m.group_id = g.id
       WHERE m.is_public = 1
       ORDER BY g.sort_order ASC, g.id ASC`
    );
    res.json(rows);
  } catch (e) {
    log('ERROR', '公开API错误', { path: req.path, method: req.method, error: e.message });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/public/monitors', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM monitors WHERE is_public = 1 ORDER BY group_id ASC, created_at DESC'
    );
    
    // 为每个监控计算24小时可用率
    const monitorsWithUptime = await Promise.all(
      rows.map(async (monitor) => {
        const [uptimeRows] = await pool.execute(
          `SELECT 
            COUNT(*) as total_checks,
            SUM(CASE WHEN status = 'up' OR status = 'warning' THEN 1 ELSE 0 END) as up_checks
          FROM check_history
          WHERE monitor_id = ? 
            AND checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
          [monitor.id]
        );
        
        const uptimeData = uptimeRows[0] || { total_checks: 0, up_checks: 0 };
        const uptime_24h = uptimeData.total_checks > 0 
          ? (uptimeData.up_checks / uptimeData.total_checks) * 100 
          : null;
        
        // 将24小时分成24个时间段（每个60分钟）
        const statusBar = [];
        const now = new Date();
        
        for (let i = 23; i >= 0; i--) {
          const startTime = new Date(now.getTime() - (i + 1) * 60 * 60 * 1000);
          const endTime = new Date(now.getTime() - i * 60 * 60 * 1000);
          
          // 查询该时间段内的所有检测记录（按时间升序，用于前端细分时间段）
          const [historyRows] = await pool.execute(
            `SELECT status, checked_at, message FROM check_history 
             WHERE monitor_id = ? AND checked_at >= ? AND checked_at < ?
             ORDER BY checked_at ASC`,
            [monitor.id, startTime, endTime]
          );
          
          if (historyRows.length === 0) {
            // 没有数据，显示灰色
            statusBar.push({ 
              status: null, 
              startTime: startTime.toISOString(), 
              endTime: endTime.toISOString(),
              totalChecks: 0,
              upChecks: 0,
              downChecks: 0,
              warningChecks: 0,
              uptime: null,
              checkRecords: []
            });
          } else {
            // 统计该时间段内的检测情况
            let totalChecks = historyRows.length;
            let upChecks = 0;
            let downChecks = 0;
            let warningChecks = 0;
            let latestCheckTime = null;
            let latestMessage = null;
            
            // 优先显示down，然后warning，最后up
            let finalStatus = null;
            
            for (const row of historyRows) {
              if (!latestCheckTime) {
                latestCheckTime = row.checked_at;
                latestMessage = row.message;
              }
              
              // 统计各状态数量
              if (row.status === 'up') {
                upChecks++;
                if (!finalStatus) {
                  finalStatus = 'up';
                }
              } else if (row.status === 'down') {
                downChecks++;
                finalStatus = 'down';
                // 找到down状态时，使用该记录的message
                latestCheckTime = row.checked_at;
                latestMessage = row.message;
              } else if (row.status === 'warning') {
                warningChecks++;
                if (finalStatus !== 'down') {
                  finalStatus = 'warning';
                  // 如果还没找到down，使用warning的message
                  if (!latestMessage || finalStatus === 'warning') {
                    latestCheckTime = row.checked_at;
                    latestMessage = row.message;
                  }
                }
              }
            }
            
            // 计算可用率（warning也算作可用）
            const uptime = totalChecks > 0 ? ((upChecks + warningChecks) / totalChecks) * 100 : null;
            
            // 将检测记录按时间排序，供前端细分时间段使用
            const checkRecords = historyRows.map(row => ({
              status: row.status,
              checked_at: row.checked_at,
              message: row.message
            }));
            
            statusBar.push({ 
              status: finalStatus || null, 
              startTime: startTime.toISOString(), 
              endTime: endTime.toISOString(), 
              checkTime: latestCheckTime ? new Date(latestCheckTime).toISOString() : null,
              message: latestMessage || null,
              totalChecks,
              upChecks,
              downChecks,
              warningChecks,
              uptime,
              checkRecords: checkRecords // 添加检测记录数组，供前端细分时间段
            });
          }
        }
        
        return {
          ...monitor,
          uptime_24h,
          statusBar24h: statusBar
        };
      })
    );
    
    res.json(monitorsWithUptime);
  } catch (e) {
    log('ERROR', '公开API错误', { path: req.path, method: req.method, error: e.message });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/public/stats', async (req, res) => {
  try {
    // 获取基础统计
    const [rows] = await pool.execute(
      `SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up,
        SUM(CASE WHEN status = 'down' THEN 1 ELSE 0 END) as down,
        SUM(CASE WHEN status = 'unknown' THEN 1 ELSE 0 END) as unknown
      FROM monitors 
      WHERE is_public = 1`
    );
    
    const stats = rows[0] || { total: 0, up: 0, down: 0, unknown: 0 };
    
    // 计算24小时可用率（warning也算作可用）
    const [uptimeRows] = await pool.execute(
      `SELECT 
        m.id,
        COUNT(*) as total_checks,
        SUM(CASE WHEN h.status = 'up' OR h.status = 'warning' THEN 1 ELSE 0 END) as up_checks
      FROM monitors m
      LEFT JOIN check_history h ON m.id = h.monitor_id 
        AND h.checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
      WHERE m.is_public = 1
      GROUP BY m.id`
    );
    
    let totalUptime = 0;
    let monitorCount = 0;
    
    uptimeRows.forEach(row => {
      if (row.total_checks > 0) {
        const uptime = (row.up_checks / row.total_checks) * 100;
        totalUptime += uptime;
        monitorCount++;
      }
    });
    
    const avgUptime = monitorCount > 0 ? (totalUptime / monitorCount) : 100;
    
    stats.uptime_24h = avgUptime;
    
    res.json(stats);
  } catch (e) {
    log('ERROR', '公开API错误', { path: req.path, method: req.method, error: e.message });
    res.status(500).json({ error: e.message });
  }
});

// ============ 页面路由（在静态文件服务之前）============
// 初始化页面
app.get('/setup', async (req, res) => {
  // 如果系统已经初始化，重定向到根路径
  try {
    const initialized = await isInitialized();
    if (initialized) {
      return res.redirect('/');
    }
  } catch (error) {
    // 如果检查失败，继续显示初始化页面
    log('WARN', '检查初始化状态失败', { error: error.message });
  }
  
  res.sendFile(path.join(__dirname, 'public', 'setup.html'));
});

// 公开展示页面 - 根路径
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'public.html'));
});

// 管理页面
app.get('/manage', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ 静态文件服务 ============
app.use(express.static(path.join(__dirname, 'public'), {
  index: false // 禁用默认的 index.html，因为我们已经手动处理了路由
}));

// 其他路由都返回管理页面（用于SPA路由，必须在静态文件服务之后）
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ 启动服务器 ============
async function start() {
  loadConfig();
  
  if (isInstalled()) {
    try {
      await connectDatabase();
      await initializeTables();
      initializeChecks();
      log('INFO', '服务器启动成功', { port: PORT });
    } catch (e) {
      log('ERROR', '连接数据库失败', { error: e.message });
      log('WARN', '请检查数据库配置或删除 config.json 重新安装');
    }
  } else {
    log('INFO', '系统未安装，等待初始化设置');
  }
  
  app.listen(PORT, () => {
    log('INFO', 'HTTP 服务器启动', { port: PORT });
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

start().catch((error) => {
  log('ERROR', '服务器启动失败', { error: error.message, stack: error.stack });
  process.exit(1);
});
