import type { RequestHandler } from 'express';

export const UI_DEV_READ_ONLY = 'UI_DEV_READ_ONLY';
export const UI_DEV_READ_ONLY_MESSAGE = 'UI 开发模式下禁止修改或执行操作';

export class UiDevReadOnlyError extends Error {
  readonly code = UI_DEV_READ_ONLY;
  readonly status = 403;

  constructor() {
    super(UI_DEV_READ_ONLY_MESSAGE);
    this.name = 'UiDevReadOnlyError';
  }
}

export function resolveUiDevMode(configValue: unknown, envValue?: string): boolean {
  if (envValue !== undefined) {
    if (envValue === 'true' || envValue === '1') return true;
    if (envValue === 'false' || envValue === '0') return false;
    throw new Error('UI_DEV_MODE 只能设置为 true、false、1 或 0');
  }
  if (configValue !== undefined && typeof configValue !== 'boolean') {
    throw new Error('配置项 uiDevMode 必须是布尔值');
  }
  return configValue === true;
}

// 初始化之前同样禁止副作用；启动后不允许切换模式。
let mode: boolean | undefined;

export function initializeRuntimeMode(configValue: unknown, envValue = process.env.UI_DEV_MODE): void {
  if (mode !== undefined) throw new Error('运行模式已初始化，修改模式需要重启');
  mode = resolveUiDevMode(configValue, envValue);
}

export function isUiDevMode(): boolean {
  return mode !== false;
}

export function assertWritable(): void {
  if (isUiDevMode()) throw new UiDevReadOnlyError();
}

export const uiDevModeMiddleware: RequestHandler = (req, res, next) => {
  const readRequest = ['GET', 'HEAD', 'OPTIONS'].includes(req.method);
  const authRequest = req.method === 'POST' &&
    ['/api/auth/login', '/api/auth/logout'].includes(req.path.toLowerCase().replace(/\/$/, ''));
  const previewRequest = req.method === 'POST' && req.path.replace(/\/$/, '') === '/api/content/preview';
  if (!isUiDevMode() || readRequest || authRequest || previewRequest) {
    next();
    return;
  }
  res.status(403).json({error: UI_DEV_READ_ONLY_MESSAGE, code: UI_DEV_READ_ONLY});
};
