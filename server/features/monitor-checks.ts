import http from 'http';
import https from 'https';
import tls from 'tls';
import dns from 'dns';
import net from 'net';
import { exec } from 'child_process';
import { URL } from 'url';
import type { MonitorRow } from '../core/db-types.js';

export interface CheckResult {
  status: string;
  responseTime: number | null;
  message: string;
  statusCode?: number;
  ssl_days_remaining?: number | null;
}

interface CheckLogger {
  debug(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

async function checkHttp(
  target: string,
  timeoutSeconds: number,
  expectedStatus: number = 200,
  authUsername: string | null = null,
  authPassword: string | null = null,
  logger: CheckLogger
): Promise<CheckResult> {
  const timeout = timeoutSeconds * 1000;
  const initialUrl = target.startsWith('http') ? target : `https://${target}`;

  const makeRequest = (url: string, redirectCount: number = 0, useHead: boolean = true): Promise<CheckResult> => {
    const requestStartTime = Date.now();
    return new Promise((resolve) => {
      if (redirectCount > 5) {
        resolve({
          status: 'down',
          responseTime: null,
          message: '重定向次数过多',
          ssl_days_remaining: null
        });
        return;
      }

      let parsedUrl: URL;
      try {
        parsedUrl = new URL(url);
      } catch (err) {
        logger.error(`URL解析失败 ${JSON.stringify({url, error: err.message, redirectCount})}`);
        resolve({
          status: 'down',
          responseTime: null,
          message: `无效的 URL: ${err.message}`,
          ssl_days_remaining: null
        });
        return;
      }

      const protocol = parsedUrl.protocol === 'https:' ? https : http;

      try {
        const dnsStart = Date.now();
        dns.lookup(parsedUrl.hostname, (dnsErr) => {
          const dnsTime = Date.now() - dnsStart;
          if (dnsErr) {
            logger.warn(`DNS 解析失败（独立检测） ${JSON.stringify({
              host: parsedUrl.hostname,
              error: dnsErr.message
            })}`);
            return;
          }
          if (dnsTime > 100) {
            logger.warn(`DNS 解析耗时（独立检测） ${JSON.stringify({
              host: parsedUrl.hostname,
              dnsTimeMs: dnsTime
            })}`);
          }
        });
      } catch (e) {
        logger.warn(`DNS 解析监控异常（独立检测） ${JSON.stringify({
          host: parsedUrl.hostname,
          error: (e as Error).message
        })}`);
      }

      const headers: Record<string, string> = {
        'User-Agent': 'Xilore UptimeBot/1.0'
      };

      if (authUsername && authPassword) {
        const auth = Buffer.from(`${authUsername}:${authPassword}`).toString('base64');
        headers.Authorization = `Basic ${auth}`;
      }

      const method = useHead ? 'HEAD' : 'GET';
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method,
        headers
      };

      const req = protocol.request(options, (res: http.IncomingMessage) => {
        const responseTime = Date.now() - requestStartTime;

        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          res.destroy();
          let redirectUrl = res.headers.location;
          if (!redirectUrl.startsWith('http')) {
            if (!redirectUrl.startsWith('/')) {
              redirectUrl = '/' + redirectUrl;
            }
            redirectUrl = `${parsedUrl.protocol}//${parsedUrl.host}${redirectUrl}`;
          }
          resolve(makeRequest(redirectUrl, redirectCount + 1, useHead));
          return;
        }

        if (useHead && (res.statusCode === 405 || res.statusCode === 501)) {
          res.destroy();
          resolve(makeRequest(url, redirectCount, false));
          return;
        }

        const success = expectedStatus === 0
          ? res.statusCode >= 200 && res.statusCode < 300
          : res.statusCode === expectedStatus;

        let ssl_days_remaining: number | null = null;
        if (res.socket && typeof (res.socket as tls.TLSSocket).getPeerCertificate === 'function') {
          try {
            const cert = (res.socket as tls.TLSSocket).getPeerCertificate();
            if (cert && cert.valid_to) {
              const validTo = new Date(cert.valid_to);
              const now = new Date();
              ssl_days_remaining = Math.floor((validTo.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));
            }
          } catch {
            // 忽略证书解析错误
          }
        }

        resolve({
          status: success ? 'up' : 'down',
          responseTime: success ? responseTime : null,
          message: `HTTP ${res.statusCode}`,
          statusCode: res.statusCode,
          ssl_days_remaining
        });
        res.destroy();
      });

      req.on('error', (err: Error) => {
        resolve({
          status: 'down',
          responseTime: null,
          message: err.message,
          ssl_days_remaining: null
        });
      });

      req.setTimeout(timeout);
      req.on('timeout', () => {
        req.destroy();
        resolve({
          status: 'down',
          responseTime: null,
          message: '请求超时',
          ssl_days_remaining: null
        });
      });

      req.end();
    });
  };

  return makeRequest(initialUrl);
}

async function checkTcp(target: string, port: number, timeoutSeconds: number): Promise<CheckResult> {
  const timeout = timeoutSeconds * 1000;
  return new Promise((resolve: (v: CheckResult) => void) => {
    const startTime = Date.now();
    const socket = new net.Socket();

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      const responseTime = Date.now() - startTime;
      socket.destroy();
      resolve({
        status: 'up',
        responseTime,
        message: `端口 ${port} 开放`
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        status: 'down',
        responseTime: null,
        message: '连接超时'
      });
    });

    socket.on('error', (err: Error) => {
      socket.destroy();
      resolve({
        status: 'down',
        responseTime: null,
        message: err.message
      });
    });

    socket.connect(port, target);
  });
}

async function checkPing(target: string, timeoutSeconds: number): Promise<CheckResult> {
  const timeout = timeoutSeconds * 1000;
  const isWin = process.platform === 'win32';
  const pingCount = 3;
  const cmd = isWin
    ? `ping -n ${pingCount} -w ${timeout} ${target}`
    : `ping -c ${pingCount} -W ${timeoutSeconds} ${target}`;

  return new Promise((resolve: (v: CheckResult) => void) => {
    const startTime = Date.now();
    exec(cmd, {timeout: timeout * pingCount + 5000}, (error: { code?: string | number; signal?: string; message?: string } | null, stdout: string | Buffer, stderr: string | Buffer) => {
      const output = String(stdout || '') + String(stderr || '');
      if (error) {
        const isTimeout = String(error.code) === 'ETIMEDOUT' || error.signal === 'SIGTERM' ||
          (error.message && error.message.includes('timeout'));
        resolve({
          status: 'down',
          responseTime: null,
          message: isTimeout ? 'Ping 超时' : '主机不可达'
        });
        return;
      }

      const timeoutOrLoss = /Request timed out|请求超时|timed out|100% loss|Lost\s*=\s*\d+\s*\(\s*100\s*%\s*\)|Received\s*=\s*0/i.test(output);
      const hasReply = /TTL=|time\s*[=<]\s*\d|时间\s*[=<]\s*\d|=\s*\d+(?:\.\d+)?\s*ms/i.test(output);
      if (timeoutOrLoss && !hasReply) {
        resolve({
          status: 'down',
          responseTime: null,
          message: 'Ping 超时'
        });
        return;
      }
      if (!hasReply) {
        resolve({
          status: 'down',
          responseTime: null,
          message: '无有效响应'
        });
        return;
      }

      let pingTime = Date.now() - startTime;
      const timeMatch = output.match(/[=<](\d+)(?:\.\d+)?(?:\s*)?(?:ms|毫秒)/i) || output.match(/time\s*[=<]\s*(\d+)/i);
      if (timeMatch) {
        pingTime = parseInt(timeMatch[1], 10);
      }
      resolve({
        status: 'up',
        responseTime: pingTime,
        message: 'Ping 成功'
      });
    });
  });
}

export async function singleCheck(monitor: MonitorRow, logger: CheckLogger): Promise<CheckResult> {
  const timeout = monitor.timeout_seconds || 10;
  const expectedStatus = monitor.expected_status || 200;

  logger.debug(`执行检测 ${JSON.stringify({
    id: monitor.id,
    name: monitor.name,
    type: monitor.type,
    target: monitor.target,
    targetType: typeof monitor.target,
    timeout,
    expectedStatus
  })}`);

  switch (monitor.type) {
    case 'http':
      return await checkHttp(monitor.target, timeout, expectedStatus, monitor.auth_username, monitor.auth_password, logger);
    case 'tcp':
      return await checkTcp(monitor.target, monitor.port, timeout);
    case 'ping':
      return await checkPing(monitor.target, timeout);
    default:
      return {status: 'unknown', responseTime: 0, message: '未知类型'};
  }
}
