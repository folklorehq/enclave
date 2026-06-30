import { createHash } from 'node:crypto';
import { buildClient, CommitmentPolicy, type KmsKeyringNode } from '@aws-crypto/client-node';
import { PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { sql } from 'drizzle-orm';
import { pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';
import neo4j from 'neo4j-driver';
import type { Db } from './client.js';

const { encrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

// column names must stay in sync with @folklore/db migrations
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

function sourceUuid(orgId: string, kind: string): string {
  const h = createHash('sha256').update(`${orgId}/${kind}`).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export interface PersistArgs {
  orgId: string;
  sourceKind: string;
  sourceFactId: string;
  occurredAt: Date;
  body: string;
}

export class EnclaveFactPersister {
  constructor(
    private readonly db: Db,
    private readonly keyring: KmsKeyringNode,
    private readonly s3: S3Client,
    private readonly mgDriver: ReturnType<typeof neo4j.driver>,
    private readonly s3Bucket: string,
  ) {}

  async persist(args: PersistArgs): Promise<string> {
    const { orgId, sourceKind, sourceFactId, occurredAt, body } = args;
    const sourceId = await this.ensureSource(orgId, sourceKind);
    const factId = await this.insertFact(orgId, sourceId, sourceFactId, occurredAt);
    const bodyS3Key = await this.encryptAndUpload(factId, orgId, body);
    await this.insertContent(factId, bodyS3Key);
    await this.mergeMemgraphNode(factId, orgId, occurredAt);
    return factId;
  }

  private async ensureSource(orgId: string, kind: string): Promise<string> {
    const id = sourceUuid(orgId, kind);
    await this.db.insert(sources).values({ id, orgId, kind }).onConflictDoNothing();
    return id;
  }

  private async insertFact(
    orgId: string,
    sourceId: string,
    sourceFactId: string,
    occurredAt: Date,
  ): Promise<string> {
    const [row] = await this.db
      .insert(facts)
      .values({ orgId, kind: 'content', sourceId, sourceFactId, occurredAt })
      .onConflictDoNothing()
      .returning({ id: facts.id });
    if (row) return row.id;
    const [existing] = await this.db
      .select({ id: facts.id })
      .from(facts)
      .where(sql`source_id = ${sourceId} AND source_fact_id = ${sourceFactId}`)
      .limit(1);
    return existing!.id;
  }

  private async encryptAndUpload(factId: string, orgId: string, body: string): Promise<string> {
    const { result } = await encrypt(this.keyring, Buffer.from(body, 'utf8'), {
      encryptionContext: { factId, orgId, purpose: 'fact-body' },
    });
    const key = `facts/${orgId}/${factId}`;
    await this.s3.send(
      new PutObjectCommand({
        Bucket: this.s3Bucket,
        Key: key,
        Body: result.toString('base64'),
        ContentType: 'text/plain',
      }),
    );
    return key;
  }

  private async insertContent(factId: string, bodyS3Key: string): Promise<void> {
    await this.db.execute(
      sql`INSERT INTO fact_content (fact_id, body_s3_key, explicit_links)
          VALUES (${factId}, ${bodyS3Key}, '[]'::jsonb)
          ON CONFLICT (fact_id) DO NOTHING`,
    );
  }

  private async mergeMemgraphNode(factId: string, orgId: string, occurredAt: Date): Promise<void> {
    const session = this.mgDriver.session();
    try {
      await session.run(
        'MERGE (f:Fact {id: $id}) SET f.orgId = $orgId, f.occurredAt = $occurredAt',
        { id: factId, orgId, occurredAt: occurredAt.toISOString() },
      );
    } finally {
      await session.close();
    }
  }
}
