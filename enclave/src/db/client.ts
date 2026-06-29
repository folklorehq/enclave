import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';

let _db: ReturnType<typeof drizzle> | null = null;

export function getDb() {
  if (!_db) {
    const client = postgres(process.env['DB_URL']!);
    _db = drizzle(client);
  }
  return _db;
}
