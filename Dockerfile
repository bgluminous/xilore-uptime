# ========== 构建阶段：编译 TypeScript ==========
FROM node:18-alpine AS builder

WORKDIR /app

# 复制依赖描述
COPY package*.json ./
# 安装全部依赖（含 devDependencies，用于 tsc）
RUN npm install

# 只复制需要参与编译的 TS 源码与配置
COPY tsconfig.json ./
COPY server ./server
COPY public ./public
COPY scripts ./scripts

# 编译 TypeScript -> dist/
RUN npm run build

# ========== 运行阶段 ==========
FROM node:18-alpine

# 安装 Ping 所需工具
RUN apk add --no-cache iputils

WORKDIR /app

ENV NODE_ENV=production

# 只安装生产依赖
COPY package*.json ./
RUN npm install --production

# 从构建阶段复制编译产物
COPY --from=builder /app/dist ./dist
# 只复制经过生产构建处理的静态资源
COPY --from=builder /app/dist/public ./public
COPY server/templates ./server/templates

# 运行时通过卷挂载 data 目录（如 /app/data）存放 config.json
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

CMD ["npm", "start"]
