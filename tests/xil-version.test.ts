import assert from 'node:assert/strict';
import {spawnSync, type SpawnSyncReturns} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import {once} from 'node:events';
import {setConfig, XilLogPropertiesConfig} from 'xilore-log4js';
import {
  encodeOfficialVersion,
  parseOfficialVersion,
  resetLocalVersionCache,
  resolveDockerArchitecture,
  resolveProjectCode,
  resolveQueryPlatform,
  versionPlatform
} from '../server/core/xil-version.js';
import {
  describeVersionQueryError,
  getVersionStatus,
  getVersionHistory,
  parsePublishedVersion,
  resetVersionQueryCache,
  resolveRegistryBase,
  VersionQueryError
} from '../server/features/version-query.js';
import {registerVersionRoutes} from '../server/routes/version.js';

setConfig(new XilLogPropertiesConfig({'detail.warn.print': 'false', 'detail.warn.write': 'false'}));

let passed = 0;
async function test(name: string, run: () => void | Promise<void>) {
  await run();
  console.log(`✓ ${name}`);
  passed++;
}

await test('正式版 1.4.0 编码与公式一致', () => {
  assert.equal(encodeOfficialVersion('1.4.0'), 10135169);
  assert.deepEqual(parseOfficialVersion('01.04.00'), {major: 1, minor: 4, patch: 0, text: '1.4.0'});
});

await test('拒绝超出 0-99 或带后缀的版本', () => {
  for (const value of ['1.4', 'v1.4.0', '1.4.0-beta', '100.0.0', '1.4.0.1', '']) {
    assert.throws(() => parseOfficialVersion(value));
  }
});

await test('Docker 架构映射到 linux 平台标识', () => {
  assert.equal(resolveDockerArchitecture('x64'), 'amd64');
  assert.equal(resolveDockerArchitecture('arm64'), 'arm64');
  assert.equal(resolveDockerArchitecture('ia32'), null);
  assert.equal(versionPlatform('docker', 'x64'), 'docker-linux-amd64');
  assert.equal(versionPlatform('dockerhub', 'aarch64'), 'dockerhub-linux-arm64');
});

await test('查询失败原因按状态分类', () => {
  assert.equal(
    describeVersionQueryError(new VersionQueryError('http', 404)),
    'GitHub 索引尚未登记该平台或版本'
  );
  assert.equal(describeVersionQueryError(new VersionQueryError('http', 503)), 'GitHub 索引暂时不可用');
  assert.equal(describeVersionQueryError(new VersionQueryError('invalid-payload')), 'GitHub 索引数据无效或版本编码不匹配');
  assert.equal(describeVersionQueryError(Object.assign(new Error('aborted'), {name: 'AbortError'})), '查询 GitHub 索引超时');
  assert.equal(describeVersionQueryError(new TypeError('fetch failed')), '无法连接 GitHub 索引');
});

await test('查询 404 会写入可读失败原因', async () => {
  resetVersionQueryCache();
  resetLocalVersionCache();
  const originalFetch = globalThis.fetch;
  const originalEnabled = process.env.VERSION_CHECK_ENABLED;
  process.env.VERSION_CHECK_ENABLED = 'true';
  globalThis.fetch = (async () => new Response(JSON.stringify({code: -1, errCode: 'NOT_FOUND'}), {
    status: 404,
    headers: {'Content-Type': 'application/json'}
  })) as typeof fetch;
  try {
    const status = await getVersionStatus();
    assert.equal(status.checkEnabled, true);
    assert.equal(status.checkFailed, true);
    assert.equal(status.checkError, 'GitHub 索引尚未登记该平台或版本');
  } finally {
    globalThis.fetch = originalFetch;
    if (originalEnabled === undefined) delete process.env.VERSION_CHECK_ENABLED;
    else process.env.VERSION_CHECK_ENABLED = originalEnabled;
    resetVersionQueryCache();
    resetLocalVersionCache();
  }
});

await test('项目与平台标识、查询地址可覆盖或关闭', () => {
  assert.equal(resolveProjectCode(undefined), 'xilore-uptime');
  assert.equal(resolveQueryPlatform('docker-linux-amd64', 'arm64'), 'docker-linux-amd64');
  assert.equal(resolveRegistryBase({VERSION_CHECK_ENABLED: 'false'}), null);
  assert.equal(resolveRegistryBase({}), 'https://raw.githubusercontent.com/bgluminous/open-source-registry/main/projects');
  assert.equal(resolveRegistryBase({VERSION_REGISTRY_REPOSITORY: 'example/versions', VERSION_REGISTRY_BRANCH: 'release/stable'}),
    'https://raw.githubusercontent.com/example/versions/release/stable/projects');
  assert.throws(() => resolveRegistryBase({VERSION_REGISTRY_REPOSITORY: 'https://user:pass@example.com'}));
  for (const branch of ['../main', 'refs//main', 'main.lock', 'main?', 'main/']) {
    assert.throws(() => resolveRegistryBase({VERSION_REGISTRY_BRANCH: branch}));
  }
  assert.throws(() => resolveProjectCode('1uptime'));
  assert.throws(() => resolveQueryPlatform('..'));
});

function resolveShell(): string | null {
  if (process.env.TEST_SH) return process.env.TEST_SH;
  const lookup = spawnSync(process.platform === 'win32' ? 'where.exe' : 'which', ['sh'], {encoding: 'utf8'});
  const fromPath = lookup.status === 0
    ? lookup.stdout.split(/\r?\n/).map(line => line.trim()).find(Boolean)
    : '';
  if (fromPath) return fromPath;
  const git = spawnSync(process.platform === 'win32' ? 'where.exe' : 'which', ['git'], {encoding: 'utf8'});
  const gitPath = git.status === 0
    ? git.stdout.split(/\r?\n/).map(line => line.trim()).find(Boolean)
    : '';
  if (!gitPath) return null;
  const sibling = path.resolve(path.dirname(gitPath), '..', 'usr', 'bin', 'sh.exe');
  return fs.existsSync(sibling) ? sibling : null;
}

await test('发布 JSON 从权威版本源生成且不打印下载地址', () => {
  const shell = resolveShell();
  assert.ok(shell, '需要 POSIX sh；可通过 TEST_SH 指定');
  resetLocalVersionCache();
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-release-'));
  const out = path.join(temp, 'release.json');
  const notes = path.join(temp, 'notes.md');
  try {
    fs.writeFileSync(notes, '# 日志\n\n## 未发布\n\n- 测试说明\n\n## 版本 1.0.0\n\n- 旧说明\n');
    const env = {...process.env, PATH: [path.dirname(shell), process.env.PATH].join(path.delimiter)};
    const result = spawnSync(shell, [
      path.resolve('scripts/xil-version/prepare-release-json.sh').replaceAll('\\', '/'),
      '--out', out.replaceAll('\\', '/'),
      '--download-url', 'https://example.com/app',
      '--image', 'bgluminous/xilore-uptime:9.9.9',
      '--arch', 'amd64',
      '--changelog-file', notes.replaceAll('\\', '/')
    ], {encoding: 'utf8', env});
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /prepared version=/);
    assert.doesNotMatch(result.stdout + result.stderr, /example\.com|bgluminous/);
    const payload = JSON.parse(fs.readFileSync(out, 'utf8'));
    const packageVersion = JSON.parse(fs.readFileSync('package.json', 'utf8')).version;
    assert.equal(payload.version, packageVersion);
    assert.equal(payload.changelog, '- 测试说明');
    assert.equal(payload.downloadUrl, 'https://example.com/app');
    assert.deepEqual(payload.extra, {image: 'bgluminous/xilore-uptime:9.9.9', arch: 'amd64'});
  } finally {
    fs.rmSync(temp, {recursive: true, force: true});
  }
});

await test('发布索引保留 UTF-8 明文与两空格缩进，兼容旧转义格式的幂等比较', () => {
  const shell = resolveShell(); assert.ok(shell);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-registry-json-'));
  const file = (name: string) => path.join(temp, name).replaceAll('\\', '/');
  const write = (name: string, text: string) => fs.writeFileSync(file(name), text, 'utf8');
  const read = (name: string) => fs.readFileSync(file(name), 'utf8');
  const input = {
    version: '1.2.3', downloadUrl: 'https://example.com/app',
    changelog: '更新 😀\n"说明"\\路径\t完成',
    extra: {'中文键😀': [false, 0, null, {}, [], {control: '\u0000\u0001\b\f\r'}]}
  };
  const env = {
    ...process.env, PATH: [path.dirname(shell), process.env.PATH].join(path.delimiter), LC_ALL: 'C',
    RELEASE_PROJECT_CODE: 'demo', RELEASE_PLATFORM_CODE: 'linux-x64',
    VP_OP: 'plan', VP_FILE: file('input.json'), VP_FILE2: file('old.json'),
    VP_LATEST: file('previous-latest.json'), VP_INDEX: file('previous-index.json'), VP_DIR: temp.replaceAll('\\', '/')
  };
  const plan = () => {
    const result = spawnSync(shell, ['-c',
      'exec awk -f scripts/version-publish/json.awk -f scripts/version-publish/release.awk'
    ], {encoding: 'utf8', env});
    assert.equal(result.status, 0, result.stderr || result.stdout);
  };
  try {
    write('input.json', JSON.stringify(input));
    write('old.json', 'null\n'); write('previous-latest.json', 'null\n'); write('previous-index.json', '[]\n');
    plan();
    assert.equal(read('outcome'), 'created\n');
    const record = read('record.json');
    assert.deepEqual(JSON.parse(record), {
      ...input, projectCode: 'demo', platformCode: 'linux-x64',
      versionCode: encodeOfficialVersion(input.version), forceUpdate: false
    });
    assert.equal(read('latest.json'), record);
    assert.deepEqual(JSON.parse(read('index.json')), [{
      version: input.version, versionCode: encodeOfficialVersion(input.version)
    }]);
    for (const name of ['record.json', 'latest.json', 'index.json']) {
      const raw = read(name);
      assert.equal(raw, JSON.stringify(JSON.parse(raw), null, 2) + '\n');
      assert.doesNotMatch(raw, /\r|\\u4e2d|\\ud83d/i);
    }
    assert.match(record, /中文键😀/); assert.match(record, /更新 😀/);
    assert.ok(record.includes('\\"说明\\"\\\\路径\\t完成'));
    assert.ok(record.includes('\\u0000\\u0001\\b\\f\\r'));

    // Previous publishers wrote compact ASCII escapes; equal content must stay unchanged.
    const legacy = (raw: string) => JSON.stringify(JSON.parse(raw)).replace(/[^\x00-\x7f]/g,
      char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`) + '\n';
    write('old.json', legacy(record));
    write('previous-latest.json', legacy(read('latest.json')));
    write('previous-index.json', legacy(read('index.json')));
    plan();
    assert.equal(read('outcome'), 'unchanged\n');
    assert.equal(read('record.json'), record);
  } finally {
    assert.equal(path.dirname(path.resolve(temp)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(temp).startsWith('uptime-registry-json-'));
    fs.rmSync(temp, {recursive: true, force: true});
  }
});

function published(version = '2.5.0', patch: Record<string, unknown> = {}) {
  return {projectCode: 'xilore-uptime', platformCode: 'dockerhub-linux-amd64', version,
    versionCode: encodeOfficialVersion(version), changelog: '## 更新\n\n- 新增 **能力**',
    downloadUrl: 'https://hub.docker.com/r/bgluminous/xilore-uptime/tags', extra: null, forceUpdate: false, ...patch};
}

await test('验证项目、平台、正式编码与字段，拒绝危险链接', () => {
  for (const patch of [
    {projectCode: 'other'}, {platformCode: 'other'}, {versionCode: 1}, {version: '02.5.0'},
    {forceUpdate: 'true'}, {forceUpdate: null}, {downloadUrl: 'javascript:alert(1)'},
    {downloadUrl: 'data:text/html,bad'}, {downloadUrl: 'https://user:secret@example.test'}, {changelog: 'a'.repeat(16001)}
  ]) assert.throws(() => parsePublishedVersion(published('2.5.0', patch), 'xilore-uptime', 'dockerhub-linux-amd64'));
  const result = parsePublishedVersion(published('2.5.0', {changelog: '<script>alert(1)</script>\n[x](javascript:alert(1))\n**安全**'}), 'xilore-uptime', 'dockerhub-linux-amd64');
  assert.doesNotMatch(result.changelogHtml, /<script|href="javascript:/);
  assert.match(result.changelogHtml, /<strong>安全<\/strong>/);
});

async function withRemote(run: (mock: {now: number; requests: string[]; reply: (url: string) => Response | Promise<Response>}) => Promise<void>) {
  const originalFetch = globalThis.fetch;
  const originalNow = Date.now;
  const keys = ['VERSION_CHECK_ENABLED', 'VERSION_PLATFORM_CODE', 'VERSION_PROJECT_CODE', 'VERSION_REGISTRY_REPOSITORY', 'VERSION_REGISTRY_BRANCH'];
  const saved = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  const mock = {now: 1800000000000, requests: [] as string[], reply: (_url: string): Response | Promise<Response> => Response.json(published())};
  process.env.VERSION_CHECK_ENABLED = 'true'; process.env.VERSION_PROJECT_CODE = 'xilore-uptime';
  process.env.VERSION_PLATFORM_CODE = 'dockerhub-linux-amd64';
  delete process.env.VERSION_REGISTRY_REPOSITORY; delete process.env.VERSION_REGISTRY_BRANCH;
  globalThis.fetch = (async (input: any) => {const url = String(input); mock.requests.push(url); return mock.reply(url);}) as typeof fetch;
  Date.now = () => mock.now;
  resetVersionQueryCache(); resetLocalVersionCache();
  try { await run(mock); } finally {
    globalThis.fetch = originalFetch; Date.now = originalNow;
    for (const key of keys) { if (saved[key] === undefined) delete process.env[key]; else process.env[key] = saved[key]; }
    resetVersionQueryCache(); resetLocalVersionCache();
  }
}

await test('读取 Raw 对象、并发合并、6 小时缓存边界与手动检查冷却', () => withRemote(async mock => {
  const [first, second] = await Promise.all([getVersionStatus(), getVersionStatus()]);
  assert.equal(mock.requests.length, 1);
  assert.match(mock.requests[0], /\/projects\/xilore-uptime\/dockerhub-linux-amd64\/latest.json$/);
  assert.equal(first.updateAvailable, true); assert.deepEqual(first, second);
  await getVersionStatus(true); assert.equal(mock.requests.length, 1);
  mock.now += 10001; await getVersionStatus(true); assert.equal(mock.requests.length, 2);
  const lastCheck = mock.now;
  mock.now = lastCheck + 10 * 60 * 1000; await getVersionStatus(); assert.equal(mock.requests.length, 2);
  mock.now = lastCheck + 6 * 60 * 60 * 1000 - 1; await getVersionStatus(); assert.equal(mock.requests.length, 2);
  mock.now += 1; await getVersionStatus(); assert.equal(mock.requests.length, 3);
}));

await test('失败保留最近成功结果和时间，恢复后清除错误', () => withRemote(async mock => {
  const first = await getVersionStatus();
  mock.now += 6 * 60 * 60 * 1000 + 1; mock.reply = () => new Response('', {status: 503});
  const failed = await getVersionStatus();
  assert.equal(failed.checkFailed, true); assert.equal(failed.updateAvailable, true);
  assert.deepEqual(failed.latest, first.latest); assert.equal(failed.lastSuccessAt, first.lastSuccessAt);
  assert.notEqual(failed.checkedAt, first.checkedAt);
  mock.now += 60001; mock.reply = () => Response.json(published('2.6.0'));
  const recovered = await getVersionStatus();
  assert.equal(recovered.checkFailed, false); assert.equal(recovered.latest?.version, '2.6.0');
}));

await test('旧 CDN 响应不会回退已发现的最新版本', () => withRemote(async mock => {
  await getVersionStatus(); mock.now += 6 * 60 * 60 * 1000 + 1; mock.reply = () => Response.json(published('2.3.0'));
  assert.equal((await getVersionStatus()).latest?.version, '2.5.0');
}));

await test('相同或较旧的发布版本不提示升级，重要更新不返回锁定命令', () => withRemote(async mock => {
  const current = JSON.parse(fs.readFileSync('package.json', 'utf8')).version;
  for (const version of [current, '1.0.0']) {
    resetVersionQueryCache(); mock.reply = () => Response.json(published(version, {forceUpdate: true}));
    const result = await getVersionStatus(); assert.equal(result.updateAvailable, false);
    assert.equal('forceUpdate' in result, false);
  }
}));

await test('关闭检查不联网，切换仓库隔离缓存，错误配置明确返回', () => withRemote(async mock => {
  process.env.VERSION_CHECK_ENABLED = 'false'; assert.equal((await getVersionStatus()).checkEnabled, false);
  assert.equal(mock.requests.length, 0);
  process.env.VERSION_CHECK_ENABLED = 'true'; await getVersionStatus();
  process.env.VERSION_REGISTRY_REPOSITORY = 'example/new-index'; await getVersionStatus();
  assert.equal(mock.requests.length, 2);
  process.env.VERSION_REGISTRY_REPOSITORY = '../bad';
  assert.equal((await getVersionStatus()).checkError, 'GitHub 版本索引配置无效');
}));

await test('无效 JSON、超大响应、旧信封和请求超时不会显示为最新版本', () => withRemote(async mock => {
  const replies = [() => new Response('{'), () => new Response(' '.repeat(262145)),
    () => Response.json({code: 0, data: published()}),
    () => {throw Object.assign(new Error(), {name: 'AbortError'});}];
  for (const reply of replies) {
    resetVersionQueryCache(); mock.reply = reply;
    const result = await getVersionStatus();
    assert.equal(result.checkFailed, true); assert.equal(result.latest, null); assert.equal(result.updateAvailable, false);
  }
}));

await test('历史按索引分页，仅请求本页版本并验证身份', () => withRemote(async mock => {
  const index = ['2.7.0', '2.6.0', '2.5.0', '2.4.0', '2.3.0', '2.2.0'].map(version => ({version, versionCode: encodeOfficialVersion(version)}));
  mock.reply = url => Response.json(url.endsWith('/index.json') ? index : published(url.match(/versions\/([\d.]+)\.json$/)![1]));
  const first = await getVersionHistory(); assert.equal(first.total, 6); assert.equal(first.items.length, 5);
  const second = await getVersionHistory(2); assert.equal(second.items[0].version, '2.2.0'); assert.equal(second.pages, 2);
  assert.equal(mock.requests.filter(url => url.endsWith('/index.json')).length, 1);
  resetVersionQueryCache(); mock.reply = url => Response.json(url.endsWith('/index.json') ? index : published('1.0.0'));
  await assert.rejects(getVersionHistory());
}));

await test('历史空数据合法，乱序与重复编码被拒绝', () => withRemote(async mock => {
  mock.reply = () => Response.json([]); assert.equal((await getVersionHistory()).total, 0);
  for (const versions of [['1.0.0', '2.0.0'], ['2.0.0', '2.0.0']]) {
    resetVersionQueryCache(); mock.reply = () => Response.json(versions.map(version => ({version, versionCode: encodeOfficialVersion(version)})));
    await assert.rejects(getVersionHistory());
  }
}));

await test('历史日志手动重试可越过失败缓存并保留最小检查间隔', () => withRemote(async mock => {
  mock.reply = () => new Response('', {status: 503});
  await assert.rejects(getVersionHistory());
  mock.reply = () => Response.json([]);
  await assert.rejects(getVersionHistory(1, true));
  assert.equal(mock.requests.length, 1);
  mock.now += 10001;
  assert.equal((await getVersionHistory(1, true)).total, 0);
  assert.equal(mock.requests.length, 2);
}));

await test('公开版本不联网；检查和日志必须登录；页码有界', async () => {
  const request = globalThis.fetch;
  await withRemote(async mock => {
    const app = express();
    registerVersionRoutes(app, {logger: {error() {}}, authMiddleware(req, res, next) {
      if (req.headers.authorization === 'Bearer synthetic') next(); else res.status(401).json({error: '未登录'});
    }});
    const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
    const address = server.address(); assert.ok(address && typeof address !== 'string');
    const base = `http://127.0.0.1:${address.port}`;
    try {
      const local = await (await request(`${base}/api/version?refresh=1`)).json();
      assert.ok(local.version); assert.equal(local.latest, undefined); assert.equal(mock.requests.length, 0);
      for (const route of ['/api/version/check?refresh=1', '/api/version/history']) assert.equal((await request(base + route)).status, 401);
      assert.equal(mock.requests.length, 0);
      const headers = {Authorization: 'Bearer synthetic'};
      assert.equal((await request(`${base}/api/version/check`, {headers})).status, 200);
      assert.equal(mock.requests.length, 1);
      for (const page of ['0', '-1', '1.5', '401', 'bad']) assert.equal((await request(`${base}/api/version/history?page=${page}`, {headers})).status, 400);
    } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
  });
});

await test('发布前校验四个 Docker 平台且拒绝分支版本不符（不构建不登记）', () => {
  const shell = resolveShell(); assert.ok(shell);
  const version = JSON.parse(fs.readFileSync('package.json', 'utf8')).version;
  const env = {...process.env, PATH: [path.dirname(shell), process.env.PATH].join(path.delimiter)};
  const script = 'ci/check-release.sh';
  const result = spawnSync(shell, [script, '--branch', `release-${version}`], {encoding: 'utf8', env});
  assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /platforms=4/);
  const invalid = spawnSync(shell, [script, '--branch', 'release-0.0.0'], {encoding: 'utf8', env});
  assert.equal(invalid.status, 2); assert.match(invalid.stderr, /E_BRANCH_VERSION_MISMATCH/);
});

await test('Docker 登记准备使用真实架构与版本，公开元数据不包含私有镜像地址', () => {
  const shell = resolveShell(); assert.ok(shell);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-version-ci-'));
  try {
    for (const relative of ['ci', 'scripts/version-publish', 'scripts/xil-version']) {
      fs.cpSync(path.resolve(relative), path.join(temp, relative), {recursive: true});
    }
    fs.copyFileSync('package.json', path.join(temp, 'package.json'));
    fs.mkdirSync(path.join(temp, 'docs')); fs.copyFileSync('docs/UPDATE_NOTE.md', path.join(temp, 'docs/UPDATE_NOTE.md'));
    fs.mkdirSync(path.join(temp, 'bin'));
    fs.writeFileSync(path.join(temp, 'bin/docker'), '#!/bin/sh\ncase "$*" in\n*Architecture*) printf "arm64\\n" ;;\n*Os*) printf "linux\\n" ;;\n*) exit 91 ;;\nesac\n', {mode: 0o755});
    const env = {...process.env, RELEASE_PROJECT_CODE: 'xilore-uptime',
      PATH: [path.join(temp, 'bin'), path.dirname(shell), process.env.PATH].join(path.delimiter)};
    const result = spawnSync(shell, ['ci/prepare-docker-release.sh', 'private.invalid/internal/app:2.4.0', 'docker-linux'],
      {encoding: 'utf8', cwd: temp, env});
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const raw = fs.readFileSync(path.join(temp, 'release-out/docker-linux-arm64/release.json'), 'utf8');
    const body = JSON.parse(raw);
    assert.equal(body.version, JSON.parse(fs.readFileSync('package.json', 'utf8')).version);
    assert.deepEqual(body.extra, {arch: 'arm64'});
    assert.ok(body.changelog); assert.match(body.downloadUrl, new RegExp(`name=${body.version}$`));
    assert.doesNotMatch(raw + result.stdout + result.stderr, /private\.invalid|internal\/app/);
    const denied = spawnSync(shell, ['ci/publish-release.sh'], {encoding: 'utf8', cwd: temp, env: {...env, CI_COMMIT_BRANCH: 'master'}});
    assert.notEqual(denied.status, 0);
  } finally {
    assert.equal(path.dirname(path.resolve(temp)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(temp).startsWith('uptime-version-ci-'));
    fs.rmSync(temp, {recursive: true, force: true});
  }
});

function withReleaseNotesFixture(run: (fixture: {
  root: string; version: string; notes: string; invoke: (script: string, args?: string[]) => SpawnSyncReturns<string>
}) => void) {
  const shell = resolveShell(); assert.ok(shell);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-release-notes-'));
  try {
    for (const relative of ['ci', 'scripts/version-publish', 'scripts/xil-version']) {
      fs.cpSync(path.resolve(relative), path.join(root, relative), {recursive: true});
    }
    for (const name of ['package.json', '.version-settings']) fs.copyFileSync(name, path.join(root, name));
    fs.mkdirSync(path.join(root, 'docs'));
    const notes = path.join(root, 'docs/UPDATE_NOTE.md');
    const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
    const env = {...process.env, RELEASE_PROJECT_CODE: 'xilore-uptime', GITHUB_ALLOW_EXTERNAL_URL: 'true',
      CI_COMMIT_BRANCH: `release-${version}`, PATH: [path.dirname(shell), process.env.PATH].join(path.delimiter)};
    const invoke = (script: string, args: string[] = []) => spawnSync(shell, [script, ...args],
      {cwd: root, encoding: 'utf8', env, timeout: 30000});
    run({root, version, notes, invoke});
  } finally {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('uptime-release-notes-'));
    fs.rmSync(root, {recursive: true, force: true});
  }
}

await test('本地发布预检与元数据准备拒绝缺失、空白和占位日志，失败保留原输出', () => withReleaseNotesFixture(f => {
  const out = path.join(f.root, 'release.json');
  const invalidNotes = [undefined, '', '## 未发布\n \t\n', '## 未发布\n\u00a0\u3000\n',
    '## 版本 0.0.0\n- 其他版本的真实变更\n',
    '## 未发布\n### 新增\n- **TODO**\n### 修复\n- [ ] 待补充。\n',
    '## 未发布\n<!-- 这里待 agent 编写\nTODO\n-->\n',
    '## 未发布\n- 首个发布版本\n',
    '## 未发布\n### 更新日志\n- 修复检测错误\n',
    `## 未发布\n- TBD\n## 版本 ${f.version}\n- 已有旧日志不能掩盖当前占位内容\n`];
  for (const notes of invalidNotes) {
    if (notes === undefined) fs.rmSync(f.notes, {force: true});
    else fs.writeFileSync(f.notes, notes, 'utf8');
    fs.writeFileSync(out, 'keep original output\n');
    const prepared = f.invoke('scripts/xil-version/prepare-release-json.sh', ['--out', out.replaceAll('\\', '/')]);
    assert.equal(prepared.status, 2, `unexpected preparation success: ${JSON.stringify(notes)}`);
    assert.equal(fs.readFileSync(out, 'utf8'), 'keep original output\n');
    const checked = f.invoke('ci/check-release.sh', ['--branch', `release-${f.version}`]);
    assert.equal(checked.status, 2, `unexpected preflight success: ${JSON.stringify(notes)}`);
    assert.equal(fs.existsSync(path.join(f.root, 'release-out')), false);
    if (notes !== undefined) assert.equal(fs.readFileSync(f.notes, 'utf8'), notes);
  }
}));

await test('日志保留正常下载与安装功能说明及全文换行，支持当前版本章节', () => withReleaseNotesFixture(f => {
  const body = '### 修复\n\n- 修复下载进度显示和安装后首次检测失败。\n- 支持带引号的名称 "😀"。\n\n';
  const out = path.join(f.root, 'release.json');
  fs.writeFileSync(f.notes, body, 'utf8');
  const prepared = f.invoke('scripts/xil-version/prepare-release-json.sh',
    ['--out', out.replaceAll('\\', '/'), '--changelog-mode', 'plain']);
  assert.equal(prepared.status, 0, prepared.stderr);
  assert.equal(JSON.parse(fs.readFileSync(out, 'utf8')).changelog, body);
  fs.writeFileSync(f.notes, `# 更新日志\n\n## 未发布\n\n## 版本 ${f.version}\n${body}`, 'utf8');
  const checked = f.invoke('ci/check-release.sh', ['--branch', `release-${f.version}`]);
  assert.equal(checked.status, 0, checked.stderr);
  assert.match(checked.stdout, /validated release changelog/);
  const selected = f.invoke('scripts/xil-version/prepare-release-json.sh', ['--out', out.replaceAll('\\', '/')]);
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(JSON.parse(fs.readFileSync(out, 'utf8')).changelog, body.trim());
}));

await test('登记前拒绝任一平台的无效日志；有效重跑复用保存的正文', () => withReleaseNotesFixture(f => {
  const publisher = path.join(f.root, 'scripts/version-publish/publish-version.sh');
  fs.copyFileSync(publisher, path.join(f.root, 'scripts/version-publish/real-publish-version.sh'));
  fs.writeFileSync(publisher, '#!/bin/sh\nset -eu\nif [ "$1" = publish ]; then\n' +
    '  printf "%s\\n" "$RELEASE_PLATFORM_CODE" >> publish.calls\n  exit 0\nfi\n' +
    'exec sh "$(dirname "$0")/real-publish-version.sh" "$@"\n');
  const files = ['docker-linux-amd64', 'dockerhub-linux-amd64'].map(platform => {
    const dir = path.join(f.root, 'release-out', platform); fs.mkdirSync(dir, {recursive: true});
    return path.join(dir, 'release.json');
  });
  const body = {version: f.version, changelog: '- 修复下载状态显示。', downloadUrl: 'https://example.com/app'};
  fs.writeFileSync(files[0], JSON.stringify(body));
  for (const changelog of [undefined, null, '', ' \n', '### 新增\n- TODO', '<!-- 待补充 -->']) {
    fs.writeFileSync(files[1], JSON.stringify({...body, changelog}));
    const result = f.invoke('ci/publish-release.sh');
    assert.equal(result.status, 2, `unexpected publish success: ${JSON.stringify(changelog)}`);
    assert.equal(fs.existsSync(path.join(f.root, 'publish.calls')), false);
  }
  fs.writeFileSync(files[1], JSON.stringify(body));
  const saved = files.map(file => fs.readFileSync(file, 'utf8'));
  const published = f.invoke('ci/publish-release.sh');
  assert.equal(published.status, 0, published.stderr);
  assert.equal(fs.existsSync(f.notes), false, 'retry must not require or regenerate source notes');
  assert.equal(fs.readFileSync(path.join(f.root, 'publish.calls'), 'utf8'), 'docker-linux-amd64\ndockerhub-linux-amd64\n');
  assert.deepEqual(files.map(file => fs.readFileSync(file, 'utf8')), saved);
}));

console.log(`\n${passed} tests passed`);
