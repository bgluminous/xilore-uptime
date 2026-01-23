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

### 前置要求

- Docker >= 20.10
- Docker Compose >= 2.0

### 快速开始

```yaml

version: '3.8'

services:
  uptimebot:
    image: bgluminous/xilore-uptime:latest
    container_name: uptimebot
    environment:
        - PORT=3000
        - CONFIG_PATH=./config.yml
        - JWT_SECRET=your-secret-key-here
    volumes:
        - /etc/localtime:/etc/localtime:ro 
        - ./config.yml:/app/config.yml

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
export CONFIG_PATH=./config.yml
export JWT_SECRET=your-secret-key-here
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
