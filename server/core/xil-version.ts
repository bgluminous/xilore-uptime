import {readFileSync} from 'node:fs';
import path from 'node:path';

export const VERSION_PROJECT_CODE = 'xilore-uptime';
export const DEFAULT_VERSION_REGISTRY = 'bgluminous/open-source-registry';
export const DEFAULT_VERSION_BRANCH = 'main';

const OFFICIAL_BIT = 1;
const ARCH_ALIASES: Record<string, 'amd64' | 'arm64'> = {
  amd64: 'amd64',
  x64: 'amd64',
  x86_64: 'amd64',
  arm64: 'arm64',
  aarch64: 'arm64'
};

export type DockerArchitecture = 'amd64' | 'arm64';
export type VersionChannel = 'docker' | 'dockerhub';

export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  text: string;
}

export interface LocalVersion {
  projectCode: string;
  version: string;
  versionCode: number;
  platform: string | null;
  architecture: DockerArchitecture | null;
}

let cachedLocal: LocalVersion | undefined;

export function parseOfficialVersion(value: string): ParsedVersion {
  const text = String(value ?? '').trim();
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (!match) throw new Error('版本号必须是 X.Y.Z');
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (![major, minor, patch].every(part => Number.isInteger(part) && part >= 0 && part <= 99)) {
    throw new Error('版本号各段必须是 0 到 99 的整数');
  }
  return {major, minor, patch, text: `${major}.${minor}.${patch}`};
}

export function encodeOfficialVersion(version: string | ParsedVersion): number {
  const parts = typeof version === 'string' ? parseOfficialVersion(version) : version;
  return 10000000 + ((parts.major << 17) | (parts.minor << 10) | (parts.patch << 3) | OFFICIAL_BIT);
}

export function resolveDockerArchitecture(arch: string = process.arch): DockerArchitecture | null {
  return ARCH_ALIASES[arch] ?? null;
}

export function versionPlatform(channel: VersionChannel, arch: string = process.arch): string | null {
  const architecture = resolveDockerArchitecture(arch);
  return architecture ? `${channel}-linux-${architecture}` : null;
}

export function resolveProjectCode(env = process.env.VERSION_PROJECT_CODE ?? process.env.XIL_PROJECT_CODE): string {
  const value = (env ?? VERSION_PROJECT_CODE).trim();
  if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(value)) {
    throw new Error('VERSION_PROJECT_CODE 不是合法的项目标识');
  }
  return value;
}

export function resolveQueryPlatform(env = process.env.VERSION_PLATFORM_CODE ?? process.env.XIL_PLATFORM_CODE, arch = process.arch): string | null {
  if (env !== undefined && env !== '') {
    const value = env.trim();
    if (!/^[a-zA-Z0-9._-]{1,32}$/.test(value) || value === '.' || value === '..') {
      throw new Error('VERSION_PLATFORM_CODE 不是合法的平台标识');
    }
    return value;
  }
  return versionPlatform('dockerhub', arch);
}

export function readLocalVersion(root = process.cwd()): LocalVersion {
  if (cachedLocal) return cachedLocal;
  const raw = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as {version?: string};
  const parsed = parseOfficialVersion(raw.version ?? '');
  cachedLocal = {
    projectCode: resolveProjectCode(),
    version: parsed.text,
    versionCode: encodeOfficialVersion(parsed),
    platform: resolveQueryPlatform(),
    architecture: resolveDockerArchitecture()
  };
  return cachedLocal;
}

export function resetLocalVersionCache(): void {
  cachedLocal = undefined;
}
