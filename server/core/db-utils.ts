import type { Pool } from 'mysql2/promise';

/** mysql2 execute 返回联合类型，统一断言为 [rows|result, fields] 便于使用 */
export async function execQuery(pool: Pool, sql: string, params?: any[]): Promise<[any, any]> {
  // noinspection ES6MissingAwait
  return pool.execute(sql, params || []) as Promise<[any, any]>;
}
