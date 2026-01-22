# 使用官方 Node.js 镜像作为基础镜像
FROM node:18-alpine

# 安装必要的系统工具（用于 Ping 功能）
RUN apk add --no-cache iputils

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV NODE_ENV=production

# 复制 package.json 和 package-lock.json
COPY package*.json ./

# 安装项目依赖
RUN npm ci --only=production && npm cache clean --force

# 复制项目文件
COPY . .

# 创建非 root 用户（安全性）
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

# 切换到非 root 用户
USER nodejs

# 暴露端口
EXPOSE 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# 启动应用
CMD ["node", "server/server.js"]
