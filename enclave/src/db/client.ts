import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';

export type Db = ReturnType<typeof createDb>;

export function createDb() {
  return drizzle(postgres(process.env['DB_URL']!));
}
