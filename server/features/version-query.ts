import {getLogger} from 'xilore-log4js';
import {
  DEFAULT_VERSION_REGISTRY, DEFAULT_VERSION_BRANCH, encodeOfficialVersion,
  parseOfficialVersion, readLocalVersion, type LocalVersion
} from '../core/xil-version.js';
import {renderContent} from './content.js';

const logger = getLogger('version-query');
const CACHE_MS = 6 * 60 * 60 * 1000;
const FAILURE_CACHE_MS = 60 * 1000;
const REFRESH_COOLDOWN_MS = 10 * 1000;
const MAX_RESPONSE_BYTES = 256 * 1024;
const HISTORY_PAGE_SIZE = 5;

export interface PublishedVersion {
  version: string;
  versionCode: number;
  changelog: string | null;
  changelogHtml: string;
  downloadUrl: string | null;
  forceUpdate: boolean;
}

export interface VersionStatus extends LocalVersion {
  source: 'github';
  latest: PublishedVersion | null;
  updateAvailable: boolean;
  checkEnabled: boolean;
  checkFailed: boolean;
  checkError: string | null;
  checkedAt: string | null;
  lastSuccessAt: string | null;
}

export class VersionQueryError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = 'VersionQueryError';
  }
}

export function describeVersionQueryError(error: unknown): string {
  if (error instanceof VersionQueryError) {
    if (error.status === 404) return 'GitHub 索引尚未登记该平台或版本';
    if (error.status === 401 || error.status === 403) return 'GitHub 索引拒绝访问，请确认仓库公开可读';
    if (error.status === 429) return '查询过于频繁，请稍后重试';
    if (error.status && error.status >= 500) return 'GitHub 索引暂时不可用';
    if (error.status) return `GitHub 索引返回 HTTP ${error.status}`;
    if (error.message === 'invalid-config') return 'GitHub 版本索引配置无效';
    if (error.message === 'disabled') return '未启用更新检查';
    if (error.message === 'invalid-payload') return 'GitHub 索引数据无效或版本编码不匹配';
  }
  if (error && typeof error === 'object' && (error as {name?: string}).name === 'AbortError') {
    return '查询 GitHub 索引超时';
  }
  if (error instanceof TypeError) return '无法连接 GitHub 索引';
  return '查询已发布版本失败';
}

export function resolveRegistryBase(env = process.env): string | null {
  if (env.VERSION_CHECK_ENABLED === 'false') return null;
  const repository = (env.VERSION_REGISTRY_REPOSITORY ?? DEFAULT_VERSION_REGISTRY).trim();
  const branch = (env.VERSION_REGISTRY_BRANCH ?? DEFAULT_VERSION_BRANCH).trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9][A-Za-z0-9._-]*$/.test(repository)
    || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(branch)
    || branch.includes('..') || branch.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.') || part.endsWith('.lock'))) {
    throw new VersionQueryError('invalid-config');
  }
  return `https://raw.githubusercontent.com/${repository}/${branch.split('/').map(encodeURIComponent).join('/')}/projects`;
}

function versionIdentity(data: unknown): {version: string; versionCode: number} {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new VersionQueryError('invalid-payload');
  const row = data as Record<string, unknown>;
  try {
    if (typeof row.version !== 'string' || parseOfficialVersion(row.version).text !== row.version
      || row.versionCode !== encodeOfficialVersion(row.version)) throw new Error();
  } catch { throw new VersionQueryError('invalid-payload'); }
  return {version: row.version as string, versionCode: row.versionCode as number};
}

export function parsePublishedVersion(data: unknown, project: string, platform: string): PublishedVersion {
  const identity = versionIdentity(data);
  const row = data as Record<string, unknown>;
  if (row.projectCode !== project || row.platformCode !== platform
    || (row.changelog != null && (typeof row.changelog !== 'string' || row.changelog.length > 16000))
    || (row.forceUpdate !== undefined && typeof row.forceUpdate !== 'boolean')) throw new VersionQueryError('invalid-payload');
  let downloadUrl: string | null = null;
  if (row.downloadUrl != null) {
    try {
      if (typeof row.downloadUrl !== 'string' || row.downloadUrl.length > 16000) throw new Error();
      const url = new URL(row.downloadUrl);
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) throw new Error();
      downloadUrl = url.href;
    } catch { throw new VersionQueryError('invalid-payload'); }
  }
  const changelog = typeof row.changelog === 'string' && row.changelog.trim() ? row.changelog : null;
  return {...identity, changelog, changelogHtml: changelog ? renderContent(changelog) : '', downloadUrl, forceUpdate: row.forceUpdate === true};
}

type IndexItem = {version: string; versionCode: number};
function parseIndex(data: unknown): IndexItem[] {
  if (!Array.isArray(data) || data.length > 2000) throw new VersionQueryError('invalid-payload');
  const index = data.map(versionIdentity);
  if (index.some((row, i) => i > 0 && row.versionCode >= index[i - 1].versionCode)) throw new VersionQueryError('invalid-payload');
  return index;
}

interface CacheEntry {
  value: unknown;
  checkedAt: number;
  lastSuccessAt: number | null;
  error: string | null;
}
const cache = new Map<string, CacheEntry>();
const inFlight = new Map<string, Promise<CacheEntry>>();

async function readJson(url: string): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(url, {redirect: 'error', signal: controller.signal, headers: {Accept: 'application/json'}});
    if (!response.ok) {
      await response.body?.cancel();
      throw new VersionQueryError('http', response.status);
    }
    if (!response.body) throw new VersionQueryError('invalid-payload');
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const {value, done} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_RESPONSE_BYTES) throw new VersionQueryError('invalid-payload');
        chunks.push(value);
      }
    } finally { await reader.cancel(); }
    try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { throw new VersionQueryError('invalid-payload'); }
  } finally { clearTimeout(timer); }
}

async function loadResource<T>(url: string, parse: (value: unknown) => T, refresh = false): Promise<CacheEntry> {
  const previous = cache.get(url);
  const ttl = refresh ? REFRESH_COOLDOWN_MS : previous?.error ? FAILURE_CACHE_MS : CACHE_MS;
  if (previous && Date.now() - previous.checkedAt < ttl) return previous;
  const pending = inFlight.get(url);
  if (pending) return pending;
  const request = (async () => {
    let entry: CacheEntry;
    try {
      let value = parse(await readJson(url));
      // Raw/CDN 可能返回旧缓存；同一来源的 latest 不得把已发现的版本退回去。
      if (url.endsWith('/latest.json') && previous?.value
        && (previous.value as PublishedVersion).versionCode > (value as PublishedVersion).versionCode) value = previous.value as T;
      entry = {value, checkedAt: Date.now(), lastSuccessAt: Date.now(), error: null};
    } catch (error) {
      const message = describeVersionQueryError(error);
      logger.warn(message);
      entry = {value: previous?.value ?? null, checkedAt: Date.now(), lastSuccessAt: previous?.lastSuccessAt ?? null, error: message};
    }
    cache.delete(url);
    cache.set(url, entry);
    while (cache.size > 100) cache.delete(cache.keys().next().value!);
    return entry;
  })();
  inFlight.set(url, request);
  try { return await request; } finally { if (inFlight.get(url) === request) inFlight.delete(url); }
}

function platformBase(local: LocalVersion): string | null {
  const base = resolveRegistryBase();
  return base && local.platform ? `${base}/${encodeURIComponent(local.projectCode)}/${encodeURIComponent(local.platform)}` : null;
}

export async function getVersionStatus(refresh = false): Promise<VersionStatus> {
  const local = readLocalVersion();
  let base: string | null;
  try { base = platformBase(local); }
  catch (error) {
    return {...local, source: 'github', latest: null, updateAvailable: false, checkEnabled: true,
      checkFailed: true, checkError: describeVersionQueryError(error), checkedAt: null, lastSuccessAt: null};
  }
  const remote = base ? await loadResource(`${base}/latest.json`, value => parsePublishedVersion(value, local.projectCode, local.platform!), refresh) : null;
  const latest = (remote?.value ?? null) as PublishedVersion | null;
  return {
    ...local, source: 'github', latest, updateAvailable: !!latest && latest.versionCode > local.versionCode,
    checkEnabled: !!base, checkFailed: !!remote?.error, checkError: remote?.error ?? null,
    checkedAt: remote ? new Date(remote.checkedAt).toISOString() : null,
    lastSuccessAt: remote?.lastSuccessAt ? new Date(remote.lastSuccessAt).toISOString() : null
  };
}

export async function getVersionHistory(page = 1, refresh = false) {
  const local = readLocalVersion();
  const base = platformBase(local);
  if (!base) throw new VersionQueryError('disabled');
  const indexResult = await loadResource(`${base}/index.json`, parseIndex, refresh);
  if (indexResult.error) throw new Error(indexResult.error);
  const index = indexResult.value as IndexItem[];
  const pages = Math.max(1, Math.ceil(index.length / HISTORY_PAGE_SIZE));
  const selectedPage = Math.min(page, pages);
  const items = await Promise.all(index.slice((selectedPage - 1) * HISTORY_PAGE_SIZE, selectedPage * HISTORY_PAGE_SIZE).map(async item => {
    const result = await loadResource(`${base}/versions/${item.version}.json`, value => {
      const version = parsePublishedVersion(value, local.projectCode, local.platform!);
      if (version.version !== item.version) throw new VersionQueryError('invalid-payload');
      return version;
    }, refresh);
    if (result.error) throw new Error(result.error);
    return result.value as PublishedVersion;
  }));
  return {items, page: selectedPage, pages, total: index.length};
}

export function resetVersionQueryCache(): void {
  cache.clear();
  inFlight.clear();
}
