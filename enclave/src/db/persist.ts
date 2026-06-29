import { createHash } from 'node:crypto';
import { sql } from 'drizzle-orm';
import { pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';
import neo4j from 'neo4j-driver';
import { getDb } from './client.js';

// Minimal table schemas — column names must stay in sync with @folklore/db migrations.
const facts = pgTable('facts', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull(),
  kind: text('kind').notNull(),
  sourceId: uuid('source_id').notNull(),
  sourceFactId: text('source_fact_id').notNull(),
  occurredAt: timestamp('occurred_at', { withTimezone: true }).notNull(),
  ingestedAt: timestamp('ingested_at', { withTimezone: true }).notNull().defaultNow(),
});

const sources = pgTable('sources', {
  id: uuid('id').primaryKey(),
  orgId: uuid('org_id').notNull(),
  kind: text('kind').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// Returns a deterministic UUID for an (orgId, kind) pair so source rows are
// idempotent across enclave restarts without a UNIQUE constraint on (orgId, kind).
function sourceUuid(orgId: string, kind: string): string {
  const h = createHash('sha256').update(`${orgId}/${kind}`).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

async function getOrCreateSourceId(orgId: string, kind: string): Promise<string> {
  const db = getDb();
  const id = sourceUuid(orgId, kind);
  await db.insert(sources).values({ id, orgId, kind }).onConflictDoNothing();
  return id;
}

let _mgDriver: ReturnType<typeof neo4j.driver> | null = null;

function getMgDriver() {
  if (!_mgDriver) {
    const url = process.env['MEMGRAPH_URL'] ?? 'bolt://localhost:7687';
    _mgDriver = neo4j.driver(url);
  }
  return _mgDriver;
}

export interface PersistArgs {
  orgId: string;
  sourceKind: string;
  sourceFactId: string;
  occurredAt: Date;
  body: string;
  embedding: number[];
}

export async function persistFact(args: PersistArgs): Promise<string> {
  const { orgId, sourceKind, sourceFactId, occurredAt, body, embedding } = args;
  const db = getDb();

  const sourceId = await getOrCreateSourceId(orgId, sourceKind);

  // Insert fact — skip silently if this (sourceId, sourceFactId) already exists.
  const [row] = await db
    .insert(facts)
    .values({ orgId, kind: 'content', sourceId, sourceFactId, occurredAt })
    .onConflictDoNothing()
    .returning({ id: facts.id });

  let factId: string;
  if (row) {
    factId = row.id;
  } else {
    // Already exists — look up the existing id.
    const [existing] = await db
      .select({ id: facts.id })
      .from(facts)
      .where(sql`source_id = ${sourceId} AND source_fact_id = ${sourceFactId}`)
      .limit(1);
    factId = existing!.id;
  }

  // Insert fact_content with halfvec embedding via raw SQL (drizzle has no built-in halfvec type).
  await db.execute(
    sql`INSERT INTO fact_content (fact_id, body, explicit_links, embedding)
        VALUES (${factId}, ${body}, '[]'::jsonb, ${`[${embedding.join(',')}]`}::halfvec)
        ON CONFLICT (fact_id) DO NOTHING`,
  );

  // Upsert Fact node in Memgraph for graph traversal.
  const session = getMgDriver().session();
  try {
    await session.run('MERGE (f:Fact {id: $id}) SET f.orgId = $orgId, f.occurredAt = $occurredAt', {
      id: factId,
      orgId,
      occurredAt: occurredAt.toISOString(),
    });
  } finally {
    await session.close();
  }

  return factId;
}
