# 部署指南

本文档提供 UptimeBot 的详细部署说明。

## 目录

- [Docker Compose 部署（推荐）](#docker-compose-部署推荐)
- [手动部署](#手动部署)
- [生产环境配置](#生产环境配置)
- [常用操作](#常用操作)
- [故障排查](#故障排查)

---

## Docker Compose 部署（推荐）

Docker 部署是最简单快速的方式，会自动配置好 MySQL 数据库和应用。

### 前置要求

- Docker >= 20.10
- Docker Compose >= 2.0

### 快速开始

#### 1. 克隆项目

```bash
git clone <your-repo-url>
cd uptime-monitor
```

#### 2. 配置环境变量

复制环境变量示例文件：

```bash
cp env.sample .env
```

编辑 `.env` 文件，修改以下关键配置：

```bash
# 应用配置
APP_PORT=3000                               # 应用访问端口
JWT_SECRET=your-secret-key-here             # JWT 密钥（生产环境必改）

# MySQL 配置
MYSQL_ROOT_PASSWORD=your_root_password      # MySQL root 密码
MYSQL_DATABASE=uptimebot                    # 数据库名
MYSQL_USER=uptimebot                        # 数据库用户
MYSQL_PASSWORD=your_db_password             # 数据库密码
MYSQL_PORT=3306                             # MySQL 端口

# 时区配置
TZ=Asia/Shanghai                            # 时区设置
```

> **安全提示**: 生产环境请务必修改所有默认密码！

生成安全的随机密码：
```bash
# 生成 JWT 密钥
openssl rand -base64 32

# 生成数据库密码
openssl rand -base64 24
```

#### 3. 启动服务

```bash
# 构建并启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f app

# 停止服务
docker-compose down

# 停止服务并删除数据
docker-compose down -v
```

#### 4. 访问应用

打开浏览器访问 `http://localhost:3000`（或您配置的端口）

首次访问会进入安装向导，配置信息如下：

**数据库配置**（使用 Docker Compose 时）:
- MySQL 主机: `mysql`（容器名称，不要改）
- 端口: `3306`
- 数据库名: `uptimebot`（与 `.env` 中的 MYSQL_DATABASE 一致）
- 用户名: `uptimebot`（与 `.env` 中的 MYSQL_USER 一致）
- 密码: 您在 `.env` 中设置的 MYSQL_PASSWORD

**管理员账户**:
- 用户名: 自定义
- 邮箱: 可选
- 密码: 至少6位

完成配置后即可登录使用。

---

## 手动部署

### 前置要求

- Node.js >= 16.0.0
- MySQL 5.7+ 或 MySQL 8.0+

### 部署步骤

#### 1. 安装依赖

```bash
npm install
```

#### 2. 准备 MySQL 数据库

确保 MySQL 服务已启动，并创建一个数据库（也可以在安装向导中让应用自动创建）。

```sql
CREATE DATABASE uptimebot CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

#### 3. 配置环境变量（可选）

```bash
export PORT=3000
export JWT_SECRET=your-secret-key-here
```

#### 4. 启动服务

```bash
npm start
```

#### 5. 初始化配置

打开浏览器访问 `http://localhost:3000`

首次访问会进入安装向导，需要配置：

**数据库配置**:
- MySQL 主机地址（如 `localhost`）
- 端口号（默认 3306）
- 数据库名（会自动创建）
- 用户名和密码

**管理员账户**:
- 用户名
- 邮箱（可选）
- 密码（至少6位）

完成配置后即可登录使用。

---

## 生产环境配置

### 1. 使用反向代理（推荐）

#### Nginx 配置示例

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # SSL 优化配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket 支持（如需要）
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

#### Caddy 配置示例

```caddyfile
your-domain.com {
    reverse_proxy localhost:3000
}
```

### 2. 使用进程管理器（手动部署时）

#### PM2 配置

安装 PM2:
```bash
npm install -g pm2
```

创建 `ecosystem.config.js`:
```javascript
module.exports = {
  apps: [{
    name: 'uptimebot',
    script: './server/server.js',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '512M',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    }
  }]
};
```

启动应用:
```bash
# 启动
pm2 start ecosystem.config.js

# 查看状态
pm2 status

# 查看日志
pm2 logs uptimebot

# 重启
pm2 restart uptimebot

# 停止
pm2 stop uptimebot

# 设置开机自启
pm2 startup
pm2 save
```

#### Systemd 服务配置

创建 `/etc/systemd/system/uptimebot.service`:
```ini
[Unit]
Description=UptimeBot Monitoring Service
After=network.target mysql.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/uptime-monitor
ExecStart=/usr/bin/node server/server.js
Restart=always
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
```

启动服务:
```bash
sudo systemctl daemon-reload
sudo systemctl enable uptimebot
sudo systemctl start uptimebot
sudo systemctl status uptimebot
```

### 3. 数据库备份

#### Docker 环境

```bash
# 备份数据库
docker-compose exec mysql mysqldump -u root -p uptimebot > backup.sql

# 压缩备份
docker-compose exec mysql mysqldump -u root -p uptimebot | gzip > backup_$(date +%Y%m%d).sql.gz

# 恢复数据库
docker-compose exec -T mysql mysql -u root -p uptimebot < backup.sql
```

#### 定时备份（Cron）

```bash
# 编辑 crontab
crontab -e

# 添加每天凌晨2点备份
0 2 * * * cd /path/to/uptime-monitor && docker-compose exec -T mysql mysqldump -u root -p${MYSQL_ROOT_PASSWORD} uptimebot | gzip > /backup/uptimebot_$(date +\%Y\%m\%d).sql.gz
```

### 4. 资源限制（Docker）

在 `docker-compose.yml` 中添加：

```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
  
  mysql:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

### 5. 安全建议

- ✅ 修改所有默认密码
- ✅ 使用 HTTPS 加密传输
- ✅ 定期更新 Docker 镜像和依赖包
- ✅ 限制 MySQL 端口仅内网访问（移除 `ports` 映射）
- ✅ 启用防火墙规则
- ✅ 定期备份数据
- ✅ 监控系统日志
- ✅ 使用强密码（至少16位，包含大小写字母、数字、特殊字符）

---

## 常用操作

### Docker 命令

```bash
# 查看运行状态
docker-compose ps

# 重启服务
docker-compose restart

# 更新镜像
docker-compose pull
docker-compose up -d

# 查看日志
docker-compose logs -f              # 所有服务
docker-compose logs -f app          # 应用服务
docker-compose logs -f mysql        # 数据库服务
docker-compose logs --tail=100 app  # 查看最后100行

# 进入容器
docker-compose exec app sh          # 进入应用容器
docker-compose exec mysql bash      # 进入数据库容器

# 清理未使用的镜像和容器
docker system prune -a
```

### 数据库操作

```bash
# 连接到 MySQL
docker-compose exec mysql mysql -u root -p

# 查看数据库
SHOW DATABASES;
USE uptimebot;
SHOW TABLES;

# 查看表结构
DESCRIBE monitors;
DESCRIBE check_history;

# 清理历史数据（保留最近7天）
DELETE FROM check_history WHERE checked_at < DATE_SUB(NOW(), INTERVAL 7 DAY);
```

### 应用更新

```bash
# 1. 备份数据
docker-compose exec mysql mysqldump -u root -p uptimebot > backup_before_update.sql

# 2. 拉取最新代码
git pull

# 3. 重新构建镜像
docker-compose build

# 4. 重启服务
docker-compose up -d

# 5. 查看日志确认
docker-compose logs -f app
```

---

## 故障排查

### 容器无法启动

```bash
# 查看详细日志
docker-compose logs -f app

# 检查容器状态
docker-compose ps

# 查看容器退出原因
docker-compose ps -a
```

### 数据库连接失败

```bash
# 确认数据库容器已启动
docker-compose ps mysql

# 检查数据库日志
docker-compose logs -f mysql

# 测试数据库连接
docker-compose exec mysql mysql -u root -p

# 检查网络连接
docker-compose exec app ping mysql
```

### 端口被占用

```bash
# 查看端口占用
netstat -ano | findstr :3000  # Windows
lsof -i :3000                 # Linux/Mac

# 修改端口（编辑 .env）
APP_PORT=3001

# 重启服务
docker-compose down
docker-compose up -d
```

### 重置配置

```bash
# 删除配置文件
rm config.json

# 重启应用
docker-compose restart app

# 访问 http://localhost:3000 重新配置
```

### Ping 功能不可用

- **Linux/Mac**: 需要 root 权限或设置 capabilities
  ```bash
  sudo setcap cap_net_raw+ep $(which node)
  ```
- **Windows**: 需要管理员权限运行
- **Docker**: 已包含 `iputils` 工具，无需额外配置

### 内存不足

```bash
# 查看容器资源使用
docker stats

# 增加 MySQL 内存限制（编辑 docker-compose.yml）
services:
  mysql:
    deploy:
      resources:
        limits:
          memory: 2G
```

### 日志过大

```bash
# 查看日志大小
docker-compose exec app du -sh /var/log

# 清理 Docker 日志
# 编辑 /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}

# 重启 Docker
sudo systemctl restart docker
```

---

## 性能优化

### 数据库优化

```sql
-- 添加索引
CREATE INDEX idx_monitor_id ON check_history(monitor_id);
CREATE INDEX idx_checked_at ON check_history(checked_at);

-- 定期清理历史数据
DELETE FROM check_history WHERE checked_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
```

### 应用优化

在 `docker-compose.yml` 中：

```yaml
services:
  app:
    environment:
      NODE_ENV: production
      NODE_OPTIONS: --max-old-space-size=512
```

---

## 监控和日志

### 日志管理

```bash
# 实时查看日志
docker-compose logs -f

# 保存日志到文件
docker-compose logs > logs.txt

# 只查看错误日志
docker-compose logs | grep ERROR
```

### 健康检查

```bash
# 检查应用健康状态
curl http://localhost:3000/

# 检查数据库健康状态
docker-compose exec mysql mysqladmin ping
```

---

## 更多帮助

如遇到其他问题，请：

1. 查看项目 [Issues](https://github.com/your-repo/issues)
2. 提交新的 Issue
3. 查看 [README.md](README.md) 了解项目基本信息

---

**文档版本**: 1.0.0  
**最后更新**: 2025-01
