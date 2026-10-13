import MarkdownIt from 'markdown-it';
import type {ContentChannel} from '../core/db-types.js';

export class ContentError extends Error {
  constructor(message: string, readonly status = 400) { super(message); }
}

const markdown = new MarkdownIt({html: false, breaks: true, linkify: false, typographer: false});
markdown.validateLink = url => /^(https?:|mailto:)/i.test(url);
// 公告无需远程图片请求；避免跟踪图片及未经限制的 data URL。
markdown.disable('image');

export function renderContent(body: string): string { return markdown.render(body); }

export function contentText(value: unknown, field: string, max: number, required = true): string {
  if (typeof value !== 'string' || value.length > max || (required && !value.trim())) {
    throw new ContentError(`${field}必须为${required ? '非空' : ''}文本，最多 ${max} 个字符`);
  }
  return value.trim();
}

export function contentBoolean(value: unknown, fallback: boolean): number {
  if (value === undefined) return Number(fallback);
  if (typeof value !== 'boolean') throw new ContentError('开关必须为布尔值');
  return Number(value);
}

export function contentChannels(value: unknown): ContentChannel[] {
  if (!Array.isArray(value) || value.some(channel => !['email', 'webhook', 'feishu'].includes(channel))) {
    throw new ContentError('请选择有效的通知渠道');
  }
  return [...new Set(value)] as ContentChannel[];
}

export function parseChannels(value: string): ContentChannel[] {
  return contentChannels(JSON.parse(value || '[]'));
}

export function contentId(value: unknown): number {
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^[1-9]\d*$/.test(value))) throw new ContentError('无效的编号');
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new ContentError('无效的编号');
  return id;
}

export function contentTime(value: unknown, field: string): number {
  if (typeof value !== 'string' || !/(Z|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new ContentError(`${field}必须包含时区`);
  }
  const time = Date.parse(value);
  if (!Number.isFinite(time)) throw new ContentError(`${field}无效`);
  return time;
}
