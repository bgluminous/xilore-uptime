# Xilore Uptime - 网站监控工具

一个简洁高效的网站监控工具，支持 HTTP、TCP 端口和 ICMP Ping 检测。

![Xilore Uptime](https://img.shields.io/badge/version-1.3.0-blue)
![Node.js](https://img.shields.io/badge/node-%3E%3D16.0.0-green)
![License](https://img.shields.io/badge/license-Luminous-orange)

## ✨ 功能特性

- 🌐 **HTTP(S) 检测** - 监控网站 HTTP/HTTPS 响应状态
- 🔌 **TCP 端口检测** - 检测指定端口是否开放
- 📡 **ICMP Ping 检测** - 检测主机是否可达
- 🎨 **安装向导** - 首次启动引导配置数据库和管理员
- 🔐 **用户认证** - JWT 登录认证，保护监控数据
- 📊 **实时仪表板** - 直观展示所有监控状态
- 📈 **历史记录** - 查看检测历史和响应时间趋势
- ⏰ **自动检测** - 可配置检测间隔（10秒-1小时）
- 📣 **通知功能** - 支持邮件和 Webhook 通知
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
    environment:
        - PORT=3000
        - CONFIG_PATH=./config.yml
        - JWT_SECRET=your-secret-key-here
    volumes:
        - /etc/localtime:/etc/localtime:ro 
        - ./data:/app/data

```

### 手动部署

```bash
# 1. 安装依赖
npm install

# 2. 启动服务
npm start

# 3. 访问 http://localhost:3000
# 首次访问将进入安装向导
```

> 📖 详细部署说明请查看 [DEPLOYMENT.md](docs/DEPLOYMENT.md)

## 📚 使用说明

### 添加监控

1. 登录后点击「添加监控」
2. 选择监控类型（HTTP / TCP / Ping）
3. 配置目标地址和检测参数
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

## 🛠️ 技术栈

- **后端**: Node.js + Express
- **数据库**: MySQL 5.7+ / 8.0
- **认证**: JWT + bcrypt
- **前端**: 原生 HTML/CSS/JavaScript

## 📁 项目结构

```
xilore-uptime/
├── public/              # 前端静态文件
|   ├── assets/          # 资源文件
│   |   ├── style.css    # 样式
│   |   ├── app.js       # 前端逻辑
│   |   ├── chart.js     # 图表
│   |   ├── setup.js     # 安装向导逻辑
│   |   ├── status.js    # 公开页逻辑
│   |   └── utils.js     # 工具
│   ├── favicon.ico      # 图标
│   ├── favicon.png      # 图标
│   ├── index.html       # 管理页
│   ├── setup.html       # 安装向导页
│   └── status.html      # 公开展示页
├── Dockerfile           # Docker 镜像配置
├── package.json         # 项目依赖
├── server.js            # 主服务文件
└── docs/DEPLOYMENT.md   # 详细部署文档
```

## ⚙️ 环境变量

主要配置项：

| 变量            | 说明     | 默认值                                 |
|---------------|--------|-------------------------------------|
| `PORT`        | 应用访问端口 | `3000`                              |
| `JWT_SECRET`  | JWT 密钥 | `change-this-secret-in-production` |
| `CONFIG_PATH` | 配置文件路径 | `./data/config.json`               |


## 📊 API 接口

### 主要接口

| 方法     | 路径                          | 说明           |
|--------|-----------------------------|--------------|
| POST   | `/api/auth/login`           | 用户登录         |
| POST   | `/api/auth/logout`          | 用户退出         |
| GET    | `/api/auth/me`              | 当前用户信息       |
| GET    | `/api/monitors`             | 获取所有监控       |
| POST   | `/api/monitors`             | 创建监控         |
| PUT    | `/api/monitors/:id`         | 更新监控         |
| DELETE | `/api/monitors/:id`         | 删除监控         |
| GET    | `/api/groups`               | 获取分组         |
| POST   | `/api/groups`               | 创建分组         |
| GET    | `/api/settings`             | 获取设置         |
| PUT    | `/api/settings`             | 更新设置         |
| GET    | `/api/public/monitors`      | 公开监控列表      |
| GET    | `/api/public/stats`         | 公开统计数据      |

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

