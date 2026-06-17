# Xilore Uptime - 网站监控工具

一个简洁高效的网站监控工具，支持 HTTP、TCP 端口和 ICMP Ping 检测。

![Xilore Uptime](https://img.shields.io/badge/version-2.3.0-blue)
![Node.js](https://img.shields.io/badge/node-%3E%3D16.0.0-green)
![License](https://img.shields.io/badge/license-Luminous-orange)

## ✨ 功能特性

- 🌐 **HTTP(S) 检测** - 监控网站 HTTP/HTTPS 响应状态，支持期望状态码、Basic Auth 和 SSL 证书剩余天数
- 🔌 **TCP 端口检测** - 检测指定端口是否开放
- 📡 **ICMP Ping 检测** - 检测主机是否可达
- 🎨 **安装向导** - 首次启动引导配置数据库和管理员
- 🔐 **用户认证** - JWT 登录认证，保护监控数据
- 📊 **实时仪表板** - 直观展示所有监控状态
- 📈 **历史记录** - 查看检测历史和响应时间趋势
- ⏰ **自动检测** - 可配置检测间隔（10秒-2小时）、超时时间和重试次数
- 📣 **通知功能** - 支持邮件、Webhook 和飞书通知，可按监控项启用，并在状态变化、警告、创建和删除时推送
- 🧩 **分组管理** - 监控分组管理与筛选
- 🧭 **公开展示页** - 对外展示服务状态
- 📱 **响应式设计** - 支持桌面和移动设备
- 🐳 **Docker 支持** - 一键部署，开箱即用

## 🚀 快速开始

### Docker 部署（推荐）

```yaml

version: '3.8'

services:
  uptimebot:
    image: bgluminous/xilore-uptime:latest
    container_name: uptimebot
    ports:
        - "3000:3000"
    environment:
        - PORT=3000
        - JWT_SECRET=your-secret-key-here
        # 可选：自定义配置文件路径（默认 /app/data/config.json）
        # - CONFIG_PATH=/app/data/config.json
    volumes:
        - /etc/localtime:/etc/localtime:ro 
        - ./data:/app/data

```

### 手动部署

```bash
# 1. 安装依赖
npm install

# 2. 启动服务
# 开发/本地运行（TypeScript 直接运行）
npm run dev

# 生产环境：先构建再启动
npm run build
npm start

# 3. 访问 http://localhost:3000
# 首次访问将进入安装向导
```

> 📖 详细部署说明请查看 [DEPLOYMENT.md](docs/DEPLOYMENT.md)  
> 📝 版本更新说明请查看 [UPDATE_NOTE.md](docs/UPDATE_NOTE.md)

## 📚 使用说明

### 添加监控

1. 登录后点击「添加监控」
2. 选择监控类型（HTTP / TCP / Ping）
3. 配置目标地址、检测参数、公开展示和通知开关
4. 保存

### 监控类型说明

| 类型        | 示例                    | 说明                   |
|-----------|-----------------------|----------------------|
| HTTP(S)   | `https://example.com` | 监控网站可用性和响应时间         |
| TCP 端口    | `example.com:3306`    | 检测端口是否开放（如数据库、Redis） |
| ICMP Ping | `8.8.8.8`             | 检测主机是否可达             |

### 查看监控数据

- **实时状态**: 主页面展示所有监控的实时状态
- **24小时可用率**: 每个监控显示24小时可用率和状态条
- **历史记录**: 点击监控项查看详细历史和图表
- **统计信息**: 查看响应时间、可用率等统计数据

### 通知配置

- **邮件通知**: 在设置中配置 SMTP 和管理员邮箱，在监控项中开启邮件提示
- **Webhook 通知**: 在设置中配置 URL、请求方法和请求头，在监控项中开启 Webhook 提示
- **飞书通知**: 在设置中配置飞书群机器人 Webhook 和可选签名密钥，在监控项中开启飞书提示

## 🛠️ 技术栈

- **后端**: Node.js + Express（TypeScript 编写，构建后运行）
- **数据库**: MySQL 5.7+ / 8.0
- **认证**: JWT + bcrypt
- **前端**: 原生 HTML/CSS/JavaScript

## 📁 项目结构

```
xilore-uptime/
├── public/              # 前端静态文件
│   ├── assets/          # 资源文件
│   │   ├── style.css    # 样式
│   │   ├── app.js       # 前端逻辑
│   │   ├── third/chart.js  # 图表（第三方库）
│   │   ├── setup.js     # 安装向导逻辑
│   │   ├── status.js    # 公开页逻辑
│   │   └── utils.js     # 工具
│   ├── favicon.ico      # 图标
│   ├── favicon.png      # 图标
│   ├── index.html       # 管理页
│   ├── setup.html       # 安装向导页
│   ├── status.html      # 公开展示页
│   └── 404.html         # 404 页面
├── server/              # 服务端源码（TypeScript）
│   ├── server.ts        # 主服务入口
│   ├── core/            # 数据库、类型、模板等基础能力
│   │   ├── database.ts  # 数据库初始化/迁移
│   │   ├── db-types.ts  # 数据库类型定义
│   │   ├── db-utils.ts  # 数据库查询工具
│   │   └── templates.ts # 邮件模板渲染工具
│   ├── features/        # 监控检测、通知、状态条等业务能力
│   │   ├── monitor-checks.ts
│   │   ├── notifications.ts
│   │   └── status-bars.ts
│   ├── routes/          # 拆分后的 API 路由
│   │   ├── groups.ts
│   │   ├── public.ts
│   │   └── settings.ts
│   └── templates/       # 邮件 HTML 模板
│       ├── monitor-status-email.template
│       └── test-email.template
├── dist/                # 构建产物（npm run build 生成）
├── Dockerfile           # Docker 镜像配置
├── package.json         # 项目依赖
├── data/                # 运行数据（默认：config.json）
└── docs/                # 部署文档与更新记录
    ├── DEPLOYMENT.md
    └── UPDATE_NOTE.md
```

## ⚙️ 环境变量

主要配置项：

| 变量            | 说明     | 默认值                                |
|---------------|--------|------------------------------------|
| `PORT`        | 应用访问端口 | `3000`                             |
| `JWT_SECRET`  | JWT 密钥 | `change-this-secret-in-production` |
| `CONFIG_PATH` | 配置文件路径 | `./data/config.json`               |


## 📊 API 接口

### 主要接口

| 方法     | 路径                                | 说明              |
|--------|-----------------------------------|-----------------|
| GET    | `/api/install/status`             | 获取安装状态          |
| POST   | `/api/install/test-db`            | 测试数据库连接         |
| POST   | `/api/install/complete`           | 完成初始化安装         |
| POST   | `/api/auth/login`                 | 用户登录            |
| POST   | `/api/auth/logout`                | 用户退出            |
| GET    | `/api/auth/me`                    | 当前用户信息          |
| GET    | `/api/monitors`                   | 获取所有监控（基础数据）    |
| GET    | `/api/monitors/statusbars`        | 获取监控状态条（24h 聚合） |
| GET    | `/api/monitors/:id`               | 获取单个监控          |
| POST   | `/api/monitors`                   | 创建监控            |
| PUT    | `/api/monitors/:id`               | 更新监控            |
| DELETE | `/api/monitors/:id`               | 删除监控            |
| POST   | `/api/monitors/:id/check`         | 手动检测单个监控        |
| GET    | `/api/monitors/:id/history`       | 获取监控历史和图表数据     |
| DELETE | `/api/monitors/:id/history`       | 清空单个监控历史        |
| DELETE | `/api/monitors/:id/history/:historyId` | 删除单条历史记录  |
| DELETE | `/api/history/all`                | 删除所有检测历史        |
| GET    | `/api/groups`                     | 获取分组            |
| POST   | `/api/groups`                     | 创建分组            |
| PUT    | `/api/groups/:id`                 | 更新分组            |
| DELETE | `/api/groups/:id`                 | 删除分组            |
| GET    | `/api/settings`                   | 获取设置            |
| PUT    | `/api/settings`                   | 更新设置            |
| POST   | `/api/settings/test-email`        | 测试邮件配置          |
| POST   | `/api/settings/test-webhook`      | 测试 Webhook 配置    |
| POST   | `/api/settings/test-feishu`       | 测试飞书配置          |
| GET    | `/api/stats`                      | 获取管理端统计数据       |
| POST   | `/api/check-all`                  | 批量检测所有启用监控      |
| GET    | `/api/public/title`               | 公开页标题           |
| GET    | `/api/public/groups`              | 公开分组列表          |
| GET    | `/api/public/monitors`            | 公开监控列表（基础数据）    |
| GET    | `/api/public/monitors/statusbars` | 公开监控状态条（24h 聚合） |
| GET    | `/api/public/stats`               | 公开统计数据          |

完整 API 文档请查看源码注释。

## 📝 许可证

本项目使用 **Luminous License** 许可证。

主要条款：
- ✅ 个人和商业用途均可免费使用
- ✅ 必须保留原始版权声明和许可声明
- ✅ 使用本项目代码必须标注来源
- ⚠️ 盈利性使用需获得作者书面同意
- ⚠️ 不得作为商业产品分发

详细内容请查看 [LICENSE](LICENSE) 文件。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📮 联系方式

如有问题或建议，请提交 Issue 或联系项目维护者。

---

