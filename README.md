# Xilore Uptime - 网站监控工具

一个简洁高效的网站监控工具，支持 HTTP、TCP 端口和 ICMP Ping 检测。

![Xilore Uptime](https://img.shields.io/badge/version-2.4.0-blue)
![Node.js](https://img.shields.io/badge/node-%3E%3D16.0.0-green)
![License](https://img.shields.io/badge/license-Luminous-orange)

## ✨ 功能特性

- 🌐 **HTTP(S) 检测** - 监控网站 HTTP/HTTPS 响应状态，支持期望状态码、Basic Auth 和 SSL 证书剩余天数
- 🔌 **TCP 端口检测** - 检测指定端口是否开放
- 📡 **ICMP Ping 检测** - 检测主机是否可达
- 🎨 **安装向导** - 首次启动引导配置数据库和管理员
- 🔐 **用户认证** - JWT 登录认证，保护监控数据
- 📊 **实时仪表板** - 侧栏工作台、服务健康概览与监控卡片，支持名称/地址搜索、状态与分组组合筛选
- 📈 **历史记录** - 查看检测历史和响应时间趋势
- ⏰ **自动检测** - 可配置检测间隔（10秒-2小时）、超时时间和重试次数
- 📣 **通知功能** - 支持邮件、Webhook 和飞书通知，可按监控项启用，并在状态变化、警告、
  创建和删除时推送
- 🧩 **分组管理** - 独立工作区页面，支持新建、改名、拖拽/按钮排序和删除，页面地址支持刷新与前进后退
- 📝 **公告管理** - Markdown 编辑与预览，支持草稿、发布、置顶、撤回及归档
- 🔧 **维护管理** - 立即或预约维护，独立控制检测、告警和统计，支持重叠时段与公开展示
- ⚙️ **系统设置** - 独立工作区页面，按工作空间、通知渠道、版本信息与数据管理分类，
  切换页面保留未保存输入
- 🏷️ **版本检查** - 管理端按运行架构查询 GitHub 版本索引，展示升级提示和更新日志
- 🧭 **公开展示页** - 紧凑展示实时状态、24 小时状态条与关键指标；清晰分组，
  支持单组/全部折叠，首次进入仅自动展开当前异常分组
- 📱 **响应式设计** - 支持桌面和移动设备
- 🌓 **全站双主题** - 管理、登录、安装、公开状态页及 404 页共享浅色/深色主题，
  默认跟随系统并记住手动选择
- ✨ **交互动效** - 分层入场、状态数值更新、分组展开、弹窗过渡与操作反馈，
  支持系统“减少动态效果”偏好
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
- **低频检测图表**: 图表聚合粒度随检测间隔调整，每小时检测一次时，
  24 小时视图显示 24 个采样点，避免正常等待时段形成空白条纹。
  保留离线与真正无记录的时段；稀疏曲线标出实际采样点，不补造响应数据
- **浅色侧栏**: 浅色主题采用雾白底与蓝紫选中态，深色主题保留石墨色导航
- **图表状态**: 红色时段表示包含离线检测，黄色表示波动，灰色表示无检测记录；
  无响应时间的离线检测仍会显示状态，悬浮可查看时段状态、检测次数与响应统计，曲线不跨越缺失响应的区间
- **详情加载**: 弹窗、趋势图和记录区预留固定空间，首次加载显示占位；
  切换时间跨度时保留原图并提示加载进度，新图仅做淡入过渡，避免采样点数量变化时曲线从底部弹起。
  画布独立于内容布局，快速切换仅展示最后选择的结果；加载失败可重试，后台刷新保留滚动位置
- **统计信息**: 管理端卡片和公开状态页显示最近 24 小时的平均延迟、P99；
  详情统计随所选时间范围更新。按全部有效原始响应计算算术平均值和最近秩 P99，
  平均值四舍五入到毫秒，不受图表聚合或历史表格 100 条上限影响；
  零毫秒参与统计，超时与无响应不参与，没有有效样本时显示 `—`。
  统计仅使用实际保留的记录。管理端指标统一为两列两行，SSL 与最后检测时间单独对齐。
- **快速筛选**: 搜索监控名称或目标地址，并组合正常、离线、波动、待检测、暂停状态与分组筛选；按 `/`
  可聚焦搜索框
- **分组展示与折叠**: 监控概览中的每个分组使用独立边框、蓝紫标题栏和卡片内容区，
  标题显示监控数量、整体状态与分组历史条；点击整行标题展开或收起，
  自动刷新时保留折叠状态。分组历史条汇总未暂停服务，离线优先于波动和正常，
  悬浮查看各时间段的服务状态数量；公开页仅统计公开服务，管理端跟随当前筛选
- **分组管理**: 侧栏「分组管理」在主内容区打开独立页面（`/manage#groups`），可创建、改名、拖拽排序、
  上下移动和删除分组；支持直接打开、刷新及浏览器前进后退，切回监控概览保留筛选条件
- **键盘操作**: 聚焦监控卡片后按 Enter 或空格打开详情；弹窗支持 Tab 循环导航和 Escape 关闭，
  手机通过顶部菜单打开侧栏
- **自动更新**: 每 30 秒同步状态，仅首次展示或筛选时播放卡片入场动画；连接失败时显示重试提示，
  暂停及尚未检测的服务不会被标记为正常

### 界面与主题

管理工作区的页脚固定在视口底部，切换页面或设置分类时保持位置；正文预留底部空间，
设置保存栏显示在页脚上方。

管理工作台、登录页、安装向导和 404 页面采用中性灰与蓝紫强调色：深色模式使用石墨灰背景，
浅色模式使用雾白背景，侧栏、按钮、弹窗和历史图表共享配色；正常状态使用低饱和绿，
离线与波动分别使用柔和红和琥珀色。公开状态页采用雾蓝底色与靛蓝强调色，以紧凑列表对齐服务名称、24
小时状态条、响应时间、可用率和最后检测时间。公开分组拥有独立边框和可折叠标题，支持全部展开/折叠；
首次进入时正常分组折叠，当前有离线或波动服务的分组展开；自动刷新保留本次手动选择，
重新打开页面后重新判断，不保存浏览偏好。顶部异常摘要分别列出离线、波动数量和服务名称。
点击日月图标切换浅色/深色主题，
主题设置同样保存在当前浏览器；启用系统“减少动态效果”后，入场、循环动画和详情图表动画会相应减少。
重设计保留 HTTP(S)/TCP/Ping 配置、全部通知通道、SSL 信息、六档历史图表、监控操作及系统设置，
不改变后端接口。

### 通知配置

侧栏「系统设置」在主内容区打开设置页面（`/manage#settings`），支持直接打开、刷新及浏览器前进后退。
基础设置、管理员账户、邮件、Webhook、飞书、版本信息与危险操作均保留；
切换分类或返回其他工作区页面时保留未保存的输入，点击「保存设置」统一保存。加载失败时可在页面重试；
退出登录会清除输入草稿。管理端侧栏和页脚显示当前版本，有更新时侧栏显示标记。
版本页展示最新发布说明、检查时间及可展开分页的历史更新日志；Docker 升级由部署者手动完成。
重要更新只加强提示，不锁定工作区。检查失败显示原因，并保留上次成功获取的版本信息。

- **邮件通知**: 在设置中配置 SMTP 和管理员邮箱，在监控项中开启邮件提示
- **Webhook 通知**: 在设置中配置 URL、请求方法和请求头，在监控项中开启 Webhook 提示
- **飞书通知**: 在设置中配置飞书群机器人 Webhook 和可选签名密钥，在监控项中开启飞书提示

### 公告与服务维护

管理员通过侧栏「公告管理」和「维护管理」操作。公告为全站内容，支持保存草稿、
发布、编辑、置顶、撤回及归档。公开页在运行概览下以时间线合并公告和维护安排，
置顶公告优先，其余按发布时间或维护开始时间倒序。默认只显示第一条，可按剩余条数展开；
公告、进行中维护、预约维护用不同颜色及文字标签区分。历史公告和维护合并放在服务列表下方，
按归档、结束或取消时间倒序，默认折叠，统一分页；展开内容和当前页在自动刷新时保留。
公告与维护的新建、编辑使用浮窗，内容区可滚动，底部固定保存和关闭按钮。
关闭按钮直接退出；第一次点击浮窗外显示提示，再点一次才关闭，继续编辑会取消关闭提示。
公告与维护共用 Markdown 编辑和预览，服务端关闭原始 HTML 和图片，
链接只允许 HTTP、HTTPS 和邮件地址。

维护可按分组批量选择服务，保存时固定具体监控项，后续分组变化不会扩大维护范围。
立即维护可不设结束时间；单次预约必须填写未来的起止时间。表单标明浏览器时区，
服务端保存 UTC 时间点，开始时刻生效、结束时刻失效。预约可取消、改期；
已开始的维护锁定范围、开始时间和处理开关，仍可修改说明、公开设置、通知渠道及结束时间。
维护可以提前结束或延期，历史始终保留。

- 「继续检测」「抑制告警」「排除统计」默认全部开启，维护默认不公开。
  重叠时段的三个限制分别合并，最后一个相关时段结束才解除对应限制。
- 维护不修改监控启用开关，原本暂停的服务不会自动恢复。停止检测时，
  单次操作明确提示、批量操作报告跳过，不生成检测记录。
- 继续检测保存真实结果，并在写入历史时固定维护及统计排除标记。
  可用率、平均延迟、P99、最小和最大延迟统一排除被标记的样本；无有效样本显示 `—`。
  原始记录仍可查看，图表和状态条标记维护区间，包括停止检测时段。
- 内部维护影响公开服务时仅显示通用维护标识；公开维护仅列出其中的公开服务，
  不返回私有名称或目标地址。分组和概览单独计数维护服务，其他服务的异常仍优先显示。
- 解除静默后安排首检；仍离线或波动时告警一次，正常时仅向维护前异常的服务发恢复通知。
  静默前状态、待复检标记和首检通知持久化，重启后继续处理。

公告和维护的主动通知默认关闭，管理员可逐条选择邮件、Webhook、飞书。
公告发布及维护预约、开始、结束、取消、改期产生事件，普通正文编辑不重复发送。
事件与渠道在数据库中去重，通知失败不回滚业务，初次失败后最多重试三次，
后台卡片可查看投递结果。队列带租约以恢复中断的投递；接收方不支持幂等时，
外部发送成功而本地确认中断可能导致重复接收。原有监控通知格式保持兼容。
协调器每五秒推进状态，检测和读取接口直接按当前时间判断；不补发已过期的开始通知。

专项验证使用 Node.js 24 的内存 SQLite 替身和通知替身：

```powershell
npm run test:communications
npm run test:ui-dev
```

测试无需编译，不连接真实数据库或通知渠道；增量迁移的真实 MySQL 验收需使用独立测试库。
界面操作采用页内确认框和提示，支持键盘操作，不使用浏览器原生弹窗。

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
│   │   ├── runtime-mode.ts
│   │   ├── templates.ts # 邮件模板渲染工具
│   │   └── xil-version.ts
│   ├── features/        # 监控检测、通知、状态条等业务能力
│   │   ├── history-chart.ts
│   │   ├── monitor-checks.ts
│   │   ├── notifications.ts
│   │   ├── status-bars.ts
│   │   └── version-query.ts
│   ├── routes/          # 拆分后的 API 路由
│   │   ├── groups.ts
│   │   ├── public.ts
│   │   ├── settings.ts
│   │   └── version.ts
│   └── templates/       # 邮件 HTML 模板
│       ├── monitor-status-email.template
│       └── test-email.template
├── dist/                # 构建产物（npm run build 生成）
├── scripts/             # 前端构建与版本登记
├── Dockerfile           # Docker 镜像配置
├── package.json         # 项目依赖
├── data/                # 运行数据（默认：config.json）
└── docs/                # 部署文档与更新记录
    ├── DEPLOYMENT.md
    └── UPDATE_NOTE.md
```

## 🧩 UI 开发只读模式

本地调试 UI 时，可以读取已有生产数据库的数据，同时禁止业务修改和后台副作用。在本地
`data/config.json` 中保留已有数据库配置与 `installed: true`，增加 `"uiDevMode": true`；也可以在
PowerShell 中启用：

```powershell
$env:CONFIG_PATH = ".\data\config.json"
$env:UI_DEV_MODE = "true"
npm run dev
```

- 环境变量 `UI_DEV_MODE` 优先于配置文件，接受 `true`、`false`、`1`、`0`；默认关闭，非法值终止启动。
  开关只在启动时读取，修改后需要重启。
- 数据库必须已经安装，并具备当前版本需要的表、字段和管理员账号。模式开启后不运行安装向导、建库、
  建表或迁移，配置、结构或连接保护校验失败会停止启动。
- 管理员仍使用已有账号登录。监控、分组、设置、公告及维护只读，
  新增、保存、删除、排序、检测和通知测试均禁用；
  筛选、详情、历史图表、主题切换、数据刷新及无副作用的 Markdown 预览可用。
- 后端统一拦截写接口和 SQL，并为每次取得的数据库连接设置会话只读；自动检测、监控补充调度、
  维护调度、历史清理及邮件/Webhook/飞书通知全部停止。无需更改数据库全局设置。
- 可额外使用仅有目标数据库查询权限的专用账号。即使使用可写账号，代码层保护仍会生效；
  正常读取仍会产生查询负载。
- `GET /api/install/status` 返回 `{ installed, initialized, uiDevMode }` 并禁止缓存。被拦截操作返回
  HTTP `403` 和 `{ error: "UI 开发模式下禁止修改或执行操作", code: "UI_DEV_READ_ONLY" }`。

设置 `UI_DEV_MODE=false` 或关闭配置项后重启，将恢复正常读写与后台任务。请为本地实例使用独立配置和
JWT 密钥，勿提交包含凭据的配置文件。

运行 `npm run test:ui-dev` 可执行隔离测试：使用合成配置、模拟数据库和真实本地 HTTP 路由，
不读取实际数据库配置，也不需要构建项目。真实 MySQL 的数据与表结构不变验收应另在独立测试库完成。

## ⚙️ 环境变量

主要配置项：

| 变量            | 说明     | 默认值                                |
|---------------|--------|------------------------------------|
| `PORT`        | 应用访问端口 | `3000`                             |
| `JWT_SECRET`  | JWT 密钥 | `change-this-secret-in-production` |
| `CONFIG_PATH` | 配置文件路径 | `./data/config.json`               |
| `UI_DEV_MODE` | UI 开发只读模式，覆盖配置文件的 `uiDevMode` | `false` |
| `VERSION_CHECK_ENABLED` | 设为 `false` 关闭远程版本检查 | `true` |
| `VERSION_REGISTRY_REPOSITORY` | 公开 GitHub 索引仓库坐标 | `bgluminous/open-source-registry` |
| `VERSION_REGISTRY_BRANCH` | GitHub 索引分支 | `main` |
| `VERSION_PROJECT_CODE` | 查询项目标识；兼容旧 `XIL_PROJECT_CODE` | `xilore-uptime` |
| `VERSION_PLATFORM_CODE` | 查询平台；兼容旧 `XIL_PLATFORM_CODE` | `dockerhub-linux-<arch>` |


## 📊 API 接口

### 主要接口

| 方法     | 路径                                | 说明              |
|--------|-----------------------------------|-----------------|
| GET    | `/api/install/status`             | 获取安装状态与 UI 开发只读模式（不缓存） |
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
| GET    | `/api/version`                    | 公开本机版本，不访问远端 |
| GET    | `/api/version/check`              | 登录后查询最新发布版本；`refresh=1` 手动检查 |
| GET    | `/api/version/history`            | 登录后读取更新日志，`page` 分页，每页 5 条 |
| GET / POST | `/api/announcements` | 公告列表 / 创建草稿或发布（管理员） |
| PUT / DELETE | `/api/announcements/:id` | 编辑含置顶 / 删除草稿（管理员） |
| POST | `/api/announcements/:id/:action` | `publish`、`withdraw`、`archive`（管理员） |
| GET / POST | `/api/maintenances` | 维护列表 / 创建维护（管理员） |
| PUT | `/api/maintenances/:id` | 修改维护，含延期和改期（管理员） |
| POST | `/api/maintenances/:id/:action` | `cancel`、`finish`（管理员） |
| POST | `/api/content/preview` | 已认证管理员的内存 Markdown 预览 |
| GET | `/api/public/announcements` | 已发布公告；`history=1` 查询归档 |
| GET | `/api/public/maintenances` | 公开维护；`history=1` 查询历史 |
| GET | `/api/public/updates` | 公告与维护合并时间线；`history=1` 查询合并历史 |

公告与维护列表使用 `page` 分页，每页 20 条，返回 `items`、`page`、`has_more`。
合并时间线另返回 `total`，只统计访客可见的内容，用于显示剩余条数。
管理端编辑与生命周期操作需携带读取时的 `revision`，版本冲突返回 `409`。
时间字段使用带时区的 ISO 8601 字符串；监控接口保留 `status`，另增 `maintenance`
及 `effective_status`，用于维护和暂停的展示。

完整 API 文档请查看源码注释。

## 📦 版本登记与平台

版本管理已接入 GitHub 索引：`bgluminous/open-source-registry` 的 `main` 分支。
镜像仍保存在原私有仓库和 Docker Hub，索引只记录公开版本元数据，不上传安装包或创建 Release。
不会把私有镜像地址写进公开索引。版本号唯一来源为 `package.json`，整数编码按公共协议生成。

| 平台标识 | 制品 |
| --- | --- |
| `docker-linux-amd64` | 私有仓库 linux/amd64 镜像 |
| `docker-linux-arm64` | 私有仓库 linux/arm64 镜像 |
| `dockerhub-linux-amd64` | Docker Hub linux/amd64 镜像 |
| `dockerhub-linux-arm64` | Docker Hub linux/arm64 镜像 |

运行实例默认按处理器架构查询 Docker Hub 的对应平台；可通过 `VERSION_PLATFORM_CODE`
选择私有仓库平台。当前 CI 只登记实际构建出的架构，不虚构其他架构的制品。

### 运行中的更新检查

管理端登录后检查更新，页面活跃时每 6 小时自动检查，也可点击“重新检查”。
服务端成功结果缓存 6 小时，失败缓存 1 分钟；手动检查保留 10 秒最小间隔，并合并并发请求。
失败时保留上次成功内容并明确提示；Raw/CDN 的旧结果不会使已发现的版本回退。
关闭检查请设置 `VERSION_CHECK_ENABLED=false`；旧 `XIL_SERVICE_URL` 已不再使用。

最新版本从下列路径读取；同目录 `index.json` 是历史索引，`versions/X.Y.Z.json`
保存指定版本的更新日志。查询不需要令牌；公开状态页只读本机版本，不触发外部查询。

```text
https://raw.githubusercontent.com/bgluminous/open-source-registry/main/projects/xilore-uptime/<platform>/latest.json
```

返回数据必须匹配项目、平台、版本号与整数编码。更新说明使用安全 Markdown 渲染，
关闭原始 HTML 和图片；制品链接仅接受无凭据的 HTTP(S) 地址。
`forceUpdate` 标记仅显示“重要更新可用”，不阻止监控管理；本项目不提供自动升级功能。
Docker 升级时由部署者拉取指定标签并重建容器，保留数据挂载和运行配置。

### 发布流程接入

`.gitlab-ci.yml` 仅在严格匹配 `release-X.Y.Z` 且分支版本等于 `package.json` 时执行：
构建并推送镜像，生成 `release-out/<platform>/release.json`，再由独立 `publish` 作业登记。
更新说明从 `docs/UPDATE_NOTE.md` 的非空“未发布”章节提取，否则匹配当前版本章节。
制品链接指向 Docker Hub 对应版本标签页；通知、检测与数据库不参与该流程。

发布前在 GitLab 配置 masked/protected 变量 `GITHUB_REGISTRY_TOKEN`，
授予索引仓库 Contents 写权限，并确保索引仓库公开可读、`main` 已初始化，且允许该身份更新。
镜像认证继续使用现有运行器配置及 `BASE_REPO_URL`；不需要信息服务发布 KEY 或项目 Release 令牌。
仓库中的脚本不会自动创建索引仓库、修改权限或绕过分支保护。

`scripts/version-publish/` 为公共发布器副本，运行依赖 POSIX `sh`、`awk`、`curl`
和基础系统工具；CI 不依赖规则仓。准备 JSON 复用现有
`scripts/xil-version/prepare-release-json.sh`；其余旧信息服务入口保留，但 CI 已不再调用。

在准备新版本提交或推送发布分支前，按根目录 `.version-settings` 执行离线预检：

```sh
sh scripts/version-publish/check-version.sh --branch release-2.4.0
```

预检读取权威版本，不构建、不上传、不登记。四个平台均校验配置，CI 只发布已有制品的平台。
`.version-settings` 不保存版本号或令牌；其中 Docker Hub 基础地址用于离线输入校验，
实际登记链接由构建作业按权威版本生成。

登记失败时，在制品有效期内单独重跑 `publish`，复用同一发布提交和原始元数据，
不会重新构建、重新提取说明或开启覆盖。CI 制品保留一天；过期后须取回原元数据再登记，
不能以重跑为由替换已发布镜像。发布器最多重试三次临时故障，冲突明确失败。
索引的版本文件、最新指针和历史列表在同一次提交更新，保留其他项目记录，禁止强推。

运行 `npm run test:version` 验证查询、鉴权、缓存、安全渲染和离线预检，无需编译应用。
本地校验不代表已经发布；登记仍需发布授权与远端凭据。

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

