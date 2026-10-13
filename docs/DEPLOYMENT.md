# 部署指南

本文档提供 UptimeBot 的详细部署说明。

## 目录

- [Docker Compose 部署（推荐）](#docker-compose-部署推荐)
- [手动部署](#手动部署)
- [生产环境配置](#生产环境配置)
- [UI 开发只读模式](#ui-开发只读模式)

---

## Docker Compose 部署（推荐）

### 前置要求

- Docker >= 20.10
- Docker Compose >= 2.0

### 快速开始

```yaml

version: '3.8'

services:
  uptime:
    image: bgluminous/xilore-uptime:{{version}}
    container_name: uptime
    environment:
        - PORT=3000
        - CONFIG_PATH=/app/data/config.json
        - JWT_SECRET=your-secret-key-here
        # 可选：关闭 GitHub 版本检查
        # - VERSION_CHECK_ENABLED=false
    volumes:
        - /etc/localtime:/etc/localtime:ro 
        - ./data:/app/data

```

## 手动部署

### 前置要求

- Node.js >= 16.0.0
- MySQL 5.7+ 或 MySQL 8.0+

### 部署步骤

#### 1. 安装依赖

```bash
npm install
```

#### 2. 配置环境变量（可选）

```bash
export PORT=3000
export CONFIG_PATH=./data/config.json
export JWT_SECRET=your-secret-key-here
# 可选：默认使用公开 GitHub 版本索引
export VERSION_REGISTRY_REPOSITORY=bgluminous/open-source-registry
export VERSION_REGISTRY_BRANCH=main
```

#### 3. 启动服务

```bash
npm start
```

## 初始化配置

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

## UI 开发只读模式

本地开发 UI 连接已有数据库时，在本地配置文件中加入 `"uiDevMode": true`，同时保留有效的 `database` 配置、`installed: true` 和本地使用的 JWT 密钥。数据库必须已有管理员及与当前程序兼容的表结构；不要通过安装向导连接生产库。

也可使用环境变量覆盖配置文件：

```powershell
$env:CONFIG_PATH = ".\data\config.json"
$env:UI_DEV_MODE = "true"
npm run dev
```

Docker 实例可在环境变量中加入 `UI_DEV_MODE=true`，并挂载本地实例专用配置。取值仅接受 `true/false/1/0`，默认关闭；修改后需重启，无法在管理页切换。

启动后检查日志和页面上的“UI 开发模式 · 只读”标识。业务字段不可编辑，
接口和数据库访问层独立拒绝修改；安装测试、迁移、自动/手动检测、历史清理及所有通知
测试和发送均被禁止。登录、查询、筛选、图表、主题切换和刷新保留。
每次取得数据库连接后先设置当前会话只读，设置失败会拒绝查询并销毁连接；
不会修改生产数据库的全局配置。

建议同时使用只有目标库查询权限的专用数据库账号。应用层保护始终启用，
不以账号已经只读为前提。配置损坏、数据库结构不兼容、管理员缺失或只读连接初始化失败
会停止启动，不降级到安装/可写模式。关闭开关并重启会恢复全部写操作和后台任务。

验证使用 `npm run test:ui-dev`，无需项目编译。该测试只使用合成数据及模拟连接；真实 MySQL 验收需使用独立测试库，分别用可写账号和只读账号检查启动、查询、被拦截操作及连接复用，确认运行前后表结构和数据一致。不要对生产库进行写入探测。

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
        
    }
}
```

**文档版本**: 1.0.0  
**最后更新**: 2025-01
