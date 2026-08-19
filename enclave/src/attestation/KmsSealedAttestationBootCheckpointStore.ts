import { createHash } from 'node:crypto';
import {
  GetObjectCommand,
  ListObjectsV2Command,
  NoSuchKey,
  PutObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import {
  parseAttestationBootCheckpoint,
  type AttestationBootCheckpoint,
  type AttestationBootCheckpointStore,
} from './AttestationBootState.js';
import { decryptRecipientCiphertext, sealKmsPayload } from '../sealing/seal.js';

const CHECKPOINT_VERSION = 1;
const CHECKPOINT_OBJECT_NAME = 'attestation-boot-checkpoint';
const BOOTSTRAP_OBJECT_NAME = 'attestation-boot-checkpoint.bootstrap';
const CHECKPOINT_PURPOSE = 'attestation-boot-checkpoint';
const BOOTSTRAP_PURPOSE = 'attestation-boot-checkpoint-bootstrap';
const RECORD_KEY_PATTERN = /^generation-(\d{10})\/(manifest_verified|kms_unsealed)$/;
const OBJECT_LOCK_RETENTION_YEARS = 100;

type KmsPayloadInput = Readonly<{
  keyId: string;
  context: Record<string, string>;
}>;

type SealPayload = (plaintext: Buffer, input: KmsPayloadInput) => Promise<Buffer>;
type UnsealPayload = (ciphertext: Buffer, input: KmsPayloadInput) => Promise<Buffer>;

export interface KmsSealedAttestationBootCheckpointStoreOptions {
  s3: S3Client;
  checkpointPrefix: string;
  kmsKeyId: string;
  orgId: string;
  deploymentId: string;
  seal?: SealPayload;
  unseal?: UnsealPayload;
}

type BootstrapMarker = Readonly<{
  version: 1;
  purpose: typeof BOOTSTRAP_PURPOSE;
  orgId: string;
  deploymentId: string;
}>;

export class KmsSealedAttestationBootCheckpointStore implements AttestationBootCheckpointStore {
  readonly #s3: S3Client;
  readonly #bucket: string;
  readonly #checkpointKey: string;
  readonly #checkpointObjectPrefix: string;
  readonly #bootstrapKey: string;
  readonly #kmsKeyId: string;
  readonly #orgId: string;
  readonly #deploymentId: string;
  readonly #seal: SealPayload;
  readonly #unseal: UnsealPayload;

  constructor(options: KmsSealedAttestationBootCheckpointStoreOptions) {
    const location = parseS3Prefix(options.checkpointPrefix);
    if (!options.s3 || !options.kmsKeyId || !options.orgId || !options.deploymentId) {
      throw new Error('attestation_boot_checkpoint_config_invalid');
    }
    this.#s3 = options.s3;
    this.#bucket = location.bucket;
    this.#checkpointKey = `${location.prefix}${CHECKPOINT_OBJECT_NAME}`;
    this.#checkpointObjectPrefix = `${this.#checkpointKey}/`;
    this.#bootstrapKey = `${location.prefix}${BOOTSTRAP_OBJECT_NAME}`;
    this.#kmsKeyId = options.kmsKeyId;
    this.#orgId = options.orgId;
    this.#deploymentId = options.deploymentId;
    this.#seal = options.seal ?? defaultSeal;
    this.#unseal = options.unseal ?? defaultUnseal;
  }

  async read(): Promise<AttestationBootCheckpoint | null> {
    const bootstrap = await this.readObject(this.#bootstrapKey);
    const recordKeys = await this.listRecordKeys();
    if (bootstrap === null && recordKeys.length === 0) return null;
    if (bootstrap === null || recordKeys.length === 0) {
      throw new Error('attestation_boot_checkpoint_missing');
    }
    this.verifyBootstrap(
      this.parseJson(await this.unsealObject(bootstrap, BOOTSTRAP_PURPOSE, this.#bootstrapKey)),
    );
    return this.readRecords(recordKeys);
  }

  async write(checkpoint: AttestationBootCheckpoint): Promise<void> {
    const parsed = parseAttestationBootCheckpoint(checkpoint);
    this.assertIdentity(parsed);
    const persisted = await this.read();
    this.assertWritable(persisted, parsed);
    await this.ensureBootstrapMarker();
    const key = this.recordKey(parsed);
    const existing = await this.readObject(key);
    if (existing !== null) {
      const current = parseAttestationBootCheckpoint(
        this.parseJson(await this.unsealObject(existing, CHECKPOINT_PURPOSE, key)),
      );
      if (!sameCheckpointIdentity(current, parsed)) {
        throw new Error('attestation_boot_checkpoint_conflict');
      }
      return;
    }
    const sealed = await this.#seal(
      Buffer.from(JSON.stringify(parsed), 'utf8'),
      this.kmsInput(CHECKPOINT_PURPOSE, key),
    );
    try {
      await this.putObject(key, sealed, '*');
    } catch {
      const raced = await this.readObject(key);
      if (raced === null) throw new Error('attestation_boot_checkpoint_write_failed');
      const current = parseAttestationBootCheckpoint(
        this.parseJson(await this.unsealObject(raced, CHECKPOINT_PURPOSE, key)),
      );
      if (!sameCheckpointIdentity(current, parsed)) {
        throw new Error('attestation_boot_checkpoint_conflict');
      }
    }
  }

  private async ensureBootstrapMarker(): Promise<void> {
    const existing = await this.readObject(this.#bootstrapKey);
    if (existing !== null) {
      this.verifyBootstrap(
        this.parseJson(await this.unsealObject(existing, BOOTSTRAP_PURPOSE, this.#bootstrapKey)),
      );
      return;
    }
    if ((await this.listRecordKeys()).length > 0) {
      throw new Error('attestation_boot_checkpoint_missing');
    }
    const marker: BootstrapMarker = {
      version: CHECKPOINT_VERSION,
      purpose: BOOTSTRAP_PURPOSE,
      orgId: this.#orgId,
      deploymentId: this.#deploymentId,
    };
    const sealed = await this.#seal(
      Buffer.from(JSON.stringify(marker), 'utf8'),
      this.kmsInput(BOOTSTRAP_PURPOSE, this.#bootstrapKey),
    );
    try {
      await this.putObject(this.#bootstrapKey, sealed, '*');
    } catch {
      const raced = await this.readObject(this.#bootstrapKey);
      if (raced === null) throw new Error('attestation_boot_checkpoint_write_failed');
      this.verifyBootstrap(
        this.parseJson(await this.unsealObject(raced, BOOTSTRAP_PURPOSE, this.#bootstrapKey)),
      );
    }
  }

  private async readRecords(keys: readonly string[]): Promise<AttestationBootCheckpoint> {
    const records: AttestationBootCheckpoint[] = [];
    const generations = new Map<number, { hash: string; hasManifest: boolean }>();
    for (const key of keys) {
      const recordKey = key.slice(this.#checkpointObjectPrefix.length);
      const match = RECORD_KEY_PATTERN.exec(recordKey);
      if (!match) throw new Error('attestation_boot_checkpoint_payload_invalid');
      const generationValue = match[1];
      if (!generationValue) throw new Error('attestation_boot_checkpoint_payload_invalid');
      const generation = Number.parseInt(generationValue, 10);
      const body = await this.readObject(key);
      if (body === null) throw new Error('attestation_boot_checkpoint_missing');
      const record = parseAttestationBootCheckpoint(
        this.parseJson(await this.unsealObject(body, CHECKPOINT_PURPOSE, key)),
      );
      if (
        record.configurationGeneration !== generation ||
        record.orgId !== this.#orgId ||
        record.deploymentId !== this.#deploymentId
      ) {
        throw new Error('attestation_boot_checkpoint_identity_invalid');
      }
      const previous = generations.get(generation);
      if (previous && previous.hash !== record.manifestHash) {
        throw new Error('attestation_boot_checkpoint_conflict');
      }
      generations.set(generation, {
        hash: record.manifestHash,
        hasManifest: (previous?.hasManifest ?? false) || record.phase === 'manifest_verified',
      });
      records.push(record);
    }
    for (const record of generations.values()) {
      if (!record.hasManifest) throw new Error('attestation_boot_checkpoint_payload_invalid');
    }
    records.sort((left, right) => {
      const generation = left.configurationGeneration - right.configurationGeneration;
      return generation !== 0 ? generation : phaseRank(left.phase) - phaseRank(right.phase);
    });
    const latest = records.at(-1);
    if (!latest) throw new Error('attestation_boot_checkpoint_missing');
    return latest;
  }

  private async listRecordKeys(): Promise<string[]> {
    const keys: string[] = [];
    let continuationToken: string | undefined;
    do {
      const response = await this.#s3.send(
        new ListObjectsV2Command({
          Bucket: this.#bucket,
          Prefix: this.#checkpointObjectPrefix,
          ...(continuationToken ? { ContinuationToken: continuationToken } : {}),
        }),
      );
      for (const item of response.Contents ?? []) {
        if (!item.Key) throw new Error('attestation_boot_checkpoint_payload_invalid');
        keys.push(item.Key);
      }
      continuationToken = response.IsTruncated ? response.NextContinuationToken : undefined;
      if (response.IsTruncated && !continuationToken) {
        throw new Error('attestation_boot_checkpoint_list_invalid');
      }
    } while (continuationToken);
    return keys.sort();
  }

  private async readObject(key: string): Promise<Buffer | null> {
    try {
      const response = await this.#s3.send(
        new GetObjectCommand({ Bucket: this.#bucket, Key: key }),
      );
      if (!response.Body) throw new Error('attestation_boot_checkpoint_object_invalid');
      return Buffer.from(await response.Body.transformToByteArray());
    } catch (error) {
      if (isMissingObject(error)) return null;
      throw error;
    }
  }

  private async putObject(key: string, body: Buffer, ifNoneMatch?: string): Promise<void> {
    await this.#s3.send(
      new PutObjectCommand({
        Bucket: this.#bucket,
        Key: key,
        Body: body,
        ContentMD5: createHash('md5').update(body).digest('base64'),
        ContentType: 'application/octet-stream',
        ObjectLockMode: 'COMPLIANCE',
        ObjectLockRetainUntilDate: new Date(
          Date.now() + OBJECT_LOCK_RETENTION_YEARS * 365 * 24 * 60 * 60 * 1000,
        ),
        ...(ifNoneMatch ? { IfNoneMatch: ifNoneMatch } : {}),
      }),
    );
  }

  private async unsealObject(body: Buffer, purpose: string, objectKey: string): Promise<Buffer> {
    try {
      return await this.#unseal(body, this.kmsInput(purpose, objectKey));
    } catch {
      throw new Error('attestation_boot_checkpoint_unseal_failed');
    }
  }

  private verifyBootstrap(value: unknown): void {
    if (
      !value ||
      typeof value !== 'object' ||
      (value as Record<string, unknown>)['version'] !== CHECKPOINT_VERSION ||
      (value as Record<string, unknown>)['purpose'] !== BOOTSTRAP_PURPOSE ||
      (value as Record<string, unknown>)['orgId'] !== this.#orgId ||
      (value as Record<string, unknown>)['deploymentId'] !== this.#deploymentId
    ) {
      throw new Error('attestation_boot_checkpoint_bootstrap_invalid');
    }
  }

  private parseJson(body: Buffer): unknown {
    try {
      return JSON.parse(body.toString('utf8')) as unknown;
    } catch {
      throw new Error('attestation_boot_checkpoint_payload_invalid');
    }
  }

  private kmsInput(purpose: string, objectKey: string): KmsPayloadInput {
    return {
      keyId: this.#kmsKeyId,
      context: {
        purpose,
        version: String(CHECKPOINT_VERSION),
        orgId: this.#orgId,
        deploymentId: this.#deploymentId,
        objectKey,
      },
    };
  }

  private assertIdentity(checkpoint: AttestationBootCheckpoint): void {
    if (checkpoint.orgId !== this.#orgId || checkpoint.deploymentId !== this.#deploymentId) {
      throw new Error('attestation_boot_checkpoint_identity_invalid');
    }
  }

  private assertWritable(
    persisted: AttestationBootCheckpoint | null,
    candidate: AttestationBootCheckpoint,
  ): void {
    if (persisted === null) return;
    if (persisted.configurationGeneration > candidate.configurationGeneration) {
      throw new Error('attestation_boot_checkpoint_superseded');
    }
    if (
      persisted.configurationGeneration === candidate.configurationGeneration &&
      persisted.manifestHash !== candidate.manifestHash
    ) {
      throw new Error('attestation_boot_checkpoint_conflict');
    }
  }

  private recordKey(checkpoint: AttestationBootCheckpoint): string {
    return `${this.#checkpointObjectPrefix}generation-${String(checkpoint.configurationGeneration).padStart(10, '0')}/${checkpoint.phase}`;
  }
}

async function defaultSeal(plaintext: Buffer, input: KmsPayloadInput): Promise<Buffer> {
  return sealKmsPayload(plaintext, input.keyId, input.context);
}

async function defaultUnseal(ciphertext: Buffer, input: KmsPayloadInput): Promise<Buffer> {
  return decryptRecipientCiphertext(ciphertext, input.keyId, input.context);
}

function parseS3Prefix(value: string): { bucket: string; prefix: string } {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('attestation_boot_checkpoint_config_invalid');
  }
  const prefix = url.pathname.replace(/^\/+/, '');
  if (url.protocol !== 's3:' || !url.hostname || !prefix || !prefix.endsWith('/')) {
    throw new Error('attestation_boot_checkpoint_config_invalid');
  }
  return { bucket: url.hostname, prefix };
}

function isMissingObject(error: unknown): boolean {
  return (
    error instanceof NoSuchKey ||
    (error instanceof Error && error.name === 'NoSuchKey') ||
    (typeof error === 'object' &&
      error !== null &&
      '$metadata' in error &&
      (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode === 404)
  );
}

function phaseRank(phase: AttestationBootCheckpoint['phase']): number {
  return phase === 'manifest_verified' ? 0 : 1;
}

function sameCheckpointIdentity(
  left: AttestationBootCheckpoint,
  right: AttestationBootCheckpoint,
): boolean {
  return (
    left.version === right.version &&
    left.phase === right.phase &&
    left.orgId === right.orgId &&
    left.deploymentId === right.deploymentId &&
    left.configurationGeneration === right.configurationGeneration &&
    left.manifestHash === right.manifestHash
  );
}
