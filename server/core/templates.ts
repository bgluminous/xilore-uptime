import fs from 'fs';
import path from 'path';

const TEMPLATE_DIR = path.join(process.cwd(), 'server', 'templates');
const templateCache = new Map<string, string>();

export function escapeHtml(input: unknown): string {
  const str = input === null || input === undefined ? '' : String(input);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function loadTemplate(filename: string): string {
  if (templateCache.has(filename)) return templateCache.get(filename) as string;
  const p = path.join(TEMPLATE_DIR, filename);
  const tpl = fs.readFileSync(p, 'utf-8');
  templateCache.set(filename, tpl);
  return tpl;
}

export function renderTemplate(filename: string, vars: Record<string, string | number | null | undefined>): string {
  const tpl = loadTemplate(filename);
  return tpl.replace(/\{\{\s*([A-Z0-9_]+)\s*}}/g, (_: string, key: string) => {
    const v = Object.prototype.hasOwnProperty.call(vars, key) ? vars[key] : '';
    return v === null || v === undefined ? '' : String(v);
  });
}
