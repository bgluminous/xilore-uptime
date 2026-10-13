import type { Pool } from 'mysql2/promise';
import { UiDevReadOnlyError } from './runtime-mode.js';

/** 事务回调只能执行 SQL，不能自行提交、关闭连接或嵌套事务。 */
export interface DatabaseExecutor {
  execute(sql: string, params?: any[]): Promise<[any, any]>;
}

export interface DatabaseClient extends DatabaseExecutor {
  transaction<T>(run: (transaction: DatabaseExecutor) => Promise<T>): Promise<T>;
  end(): Promise<void>;
}

export function assertReadOnlySql(sql: string): void {
  // SQL 来自源码，用户值通过参数传入。保守拒绝注释和分号，避免可执行注释及多语句绕过。
  if (typeof sql !== 'string' || /;|\/\*|\*\/|--|#/.test(sql)) throw new UiDevReadOnlyError();
  const statement = sql.trim();
  const showMetadata = /^SHOW\s+(?:FULL\s+)?(?:TABLES|COLUMNS)\b/i.test(statement);
  if (!showMetadata && !/^SELECT\s/i.test(statement)) throw new UiDevReadOnlyError();

  // 忽略字符串常量中的词，但保留带反引号的标识符以识别函数及关键字。
  const tokens = statement.replace(/'(?:''|\\.|[^'\\])*'/g, "''").replace(/[`\"]/g, '');
  if (/\b(?:INTO|FOR\s+(?:UPDATE|SHARE)|LOCK\s+IN\s+SHARE\s+MODE)\b/i.test(tokens) ||
      /\b(?:GET_LOCK|RELEASE_LOCK|RELEASE_ALL_LOCKS|SLEEP|BENCHMARK|LOAD_FILE|MASTER_POS_WAIT|SOURCE_POS_WAIT|WAIT_FOR_EXECUTED_GTID_SET)\s*\(/i.test(tokens)) {
    throw new UiDevReadOnlyError();
  }
}

export function createDatabaseClient(pool: Pool, readOnly: boolean): DatabaseClient {
  return Object.freeze({
    async execute(sql: string, params: any[] = []): Promise<[any, any]> {
      if (!readOnly) return pool.execute(sql, params);
      assertReadOnlySql(sql);
      const connection = await pool.getConnection();
      try {
        // 必须在当前连接的业务查询之前完成；重用连接时也重新设置。
        await connection.query('SET SESSION TRANSACTION READ ONLY');
      } catch (error) {
        connection.destroy();
        throw error;
      }
      try {
        return await connection.execute(sql, params);
      } finally {
        connection.release();
      }
    },
    async transaction<T>(run: (transaction: DatabaseExecutor) => Promise<T>): Promise<T> {
      if (readOnly) throw new UiDevReadOnlyError();
      const connection = await pool.getConnection();
      let active = true;
      let destroyed = false;
      const transaction = Object.freeze({
        async execute(sql: string, params: any[] = []): Promise<[any, any]> {
          if (!active) throw new Error('事务已经结束');
          if (!/^\s*(SELECT|INSERT|UPDATE|DELETE)\s/i.test(sql) || /;|\/\*|\*\/|--|#/.test(sql)) {
            throw new Error('事务只允许参数化的数据操作');
          }
          return connection.execute(sql, params);
        }
      });
      try {
        await connection.beginTransaction();
        const result = await run(transaction);
        active = false;
        await connection.commit();
        return result;
      } catch (error) {
        try { await connection.rollback(); }
        catch { connection.destroy(); destroyed = true; }
        throw error;
      } finally {
        active = false;
        if (!destroyed) connection.release();
      }
    },
    end: () => pool.end()
  });
}

/** mysql2 execute 返回联合类型，统一断言为 [rows|result, fields] 便于使用 */
export async function execQuery(pool: DatabaseExecutor, sql: string, params?: any[]): Promise<[any, any]> {
  // noinspection ES6MissingAwait
  return pool.execute(sql, params || []) as Promise<[any, any]>;
}
