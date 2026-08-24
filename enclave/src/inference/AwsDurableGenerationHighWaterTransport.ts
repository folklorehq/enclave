import { GetItemCommand, type DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { GetObjectCommand, ListObjectVersionsCommand, type S3Client } from '@aws-sdk/client-s3';
import {
  highWaterLogEntryV1Schema,
  highWaterPointerV1Schema,
  type DurableGenerationHighWaterTransportContextV1,
  type GenerationHighWaterRuntimeConfigV1,
  type HighWaterLogEntryV1,
} from '@folklore/contracts';
import { decode, encode, rfc8949EncodeOptions } from 'cborg';
import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import type {
  DurableGenerationHighWaterEnvelopeV1,
  DurableGenerationHighWaterTransport,
} from './DurableGenerationHighWaterClient.js';

const MAX_HIGH_WATER_BODY_BYTES = 1_048_576;
const MAX_HIGH_WATER_SCAN_PAGES = 1_024;
const MAX_HIGH_WATER_SCAN_VERSIONS = 4_096;
const MAX_HIGH_WATER_SCAN_OBJECT_BYTES = 67_108_864;
const POINTER_ATTRIBUTE_NAMES = [
  'pointerVersion',
  'contextKey',
  'orgId',
  'deploymentId',
  'logSequence',
  'entryDigest',
  'checkpointDigest',
  'objectKey',
  'objectVersionId',
  'pointerState',
  'updatedAtTrustedMs',
] as const;

export interface AwsDurableGenerationHighWaterTransportConfig {
  readonly config: GenerationHighWaterRuntimeConfigV1;
  readonly s3: Pick<S3Client, 'send'>;
  readonly dynamodb: Pick<DynamoDBClient, 'send'>;
}

export class AwsDurableGenerationHighWaterTransport implements DurableGenerationHighWaterTransport {
  private readonly signerKey: KeyObject;

  constructor(private readonly options: AwsDurableGenerationHighWaterTransportConfig) {
    this.signerKey = createPublicKey({
      key: Buffer.from(this.options.config.signerPublicKeySpki, 'base64'),
      format: 'der',
      type: 'spki',
    });
    const fingerprint = createHash('sha256')
      .update(this.signerKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    if (fingerprint !== this.options.config.signerPublicKeyFingerprint) {
      throw new Error('high_water_signer_fingerprint_mismatch');
    }
  }

  async read(
    context: DurableGenerationHighWaterTransportContextV1,
  ): Promise<DurableGenerationHighWaterEnvelopeV1> {
    const pointer = await this.readPointer(context);
    const authoritative = await this.readAuthoritativeEntry(context);
    if (pointer.logSequence > authoritative.entry.logSequence) {
      throw new Error('high_water_pointer_omission');
    }
    if (pointer.logSequence < authoritative.entry.logSequence) {
      throw new Error('high_water_pointer_regressed');
    }
    if (
      pointer.objectKey !== this.objectKey(context, authoritative.entry.logSequence) ||
      pointer.objectVersionId !== authoritative.versionId ||
      pointer.entryDigest !== authoritative.entry.entryDigest ||
      pointer.checkpointDigest !== authoritative.entry.checkpoint.checkpointDigest
    ) {
      throw new Error('high_water_pointer_object_mismatch');
    }
    return { entry: authoritative.entry, bytes: authoritative.bytes };
  }

  async commit(_input: {
    context: DurableGenerationHighWaterTransportContextV1;
    entry: HighWaterLogEntryV1;
    bytes: Uint8Array;
  }): Promise<DurableGenerationHighWaterEnvelopeV1> {
    throw new Error('high_water_transport_read_only');
  }

  private async readAuthoritativeEntry(
    context: DurableGenerationHighWaterTransportContextV1,
  ): Promise<DurableGenerationHighWaterEnvelopeV1 & { versionId: string }> {
    const versions = await this.listSequenceVersions(context);
    let previous: HighWaterLogEntryV1 | null = null;
    let highest: (DurableGenerationHighWaterEnvelopeV1 & { versionId: string }) | null = null;
    let totalObjectBytes = 0;
    for (const version of versions) {
      const response = await this.options.s3.send(
        new GetObjectCommand({
          Bucket: this.options.config.bucket,
          Key: version.key,
          VersionId: version.versionId,
        }),
      );
      if (response.VersionId !== version.versionId) {
        throw new Error('high_water_object_version_mismatch');
      }
      if (typeof response.ContentLength === 'number') {
        totalObjectBytes = this.addScanObjectBytes(totalObjectBytes, response.ContentLength);
      }
      const bytes = await this.readBoundedBody(response.Body);
      if (typeof response.ContentLength !== 'number') {
        totalObjectBytes = this.addScanObjectBytes(totalObjectBytes, bytes.byteLength);
      }
      const entry = this.decodeCanonicalEntry(bytes);
      this.assertChainEntry(context, entry, version.sequence, previous);
      this.verifyEntrySignature(entry);
      highest = { entry, bytes, versionId: version.versionId };
      previous = entry;
    }
    if (!highest) throw new Error('high_water_sequence_missing');
    return highest;
  }

  private async listSequenceVersions(
    context: DurableGenerationHighWaterTransportContextV1,
  ): Promise<readonly { sequence: number; key: string; versionId: string }[]> {
    const prefix = this.sequencePrefix(context);
    const versions = new Map<number, { sequence: number; key: string; versionId: string }>();
    let keyMarker: string | undefined;
    let versionIdMarker: string | undefined;
    const seenMarkerPairs = new Set<string>();
    let pageCount = 0;
    do {
      pageCount += 1;
      if (pageCount > MAX_HIGH_WATER_SCAN_PAGES) {
        throw new Error('high_water_scan_bound_exceeded');
      }
      const response = await this.options.s3.send(
        new ListObjectVersionsCommand({
          Bucket: this.options.config.bucket,
          Prefix: prefix,
          KeyMarker: keyMarker,
          VersionIdMarker: versionIdMarker,
        }),
      );
      if (Array.isArray(response.DeleteMarkers) && response.DeleteMarkers.length > 0) {
        throw new Error('high_water_sequence_stale_finalized_state');
      }
      for (const objectVersion of response.Versions ?? []) {
        const key = objectVersion.Key;
        const versionId = objectVersion.VersionId;
        if (typeof key !== 'string' || typeof versionId !== 'string') {
          throw new Error('high_water_sequence_invalid');
        }
        const sequence = this.sequenceFromKey(context, key);
        if (versions.has(sequence)) throw new Error('high_water_sequence_fork');
        if (versions.size >= MAX_HIGH_WATER_SCAN_VERSIONS) {
          throw new Error('high_water_scan_bound_exceeded');
        }
        versions.set(sequence, { sequence, key, versionId });
      }
      keyMarker = response.NextKeyMarker;
      versionIdMarker = response.NextVersionIdMarker;
      if (response.IsTruncated === true) {
        if (keyMarker === undefined || versionIdMarker === undefined) {
          throw new Error('high_water_pagination_invalid');
        }
        const markerPair = `${keyMarker}\u0000${versionIdMarker}`;
        if (seenMarkerPairs.has(markerPair)) {
          throw new Error('high_water_pagination_repeated');
        }
        seenMarkerPairs.add(markerPair);
      } else if (keyMarker !== undefined || versionIdMarker !== undefined) {
        throw new Error('high_water_pagination_invalid');
      }
    } while (keyMarker !== undefined || versionIdMarker !== undefined);
    const ordered = [...versions.values()].sort((left, right) => left.sequence - right.sequence);
    ordered.forEach((version, index) => {
      if (version.sequence !== index + 1) throw new Error('high_water_sequence_gap');
    });
    return ordered;
  }

  private addScanObjectBytes(totalObjectBytes: number, objectBytes: number): number {
    if (!Number.isSafeInteger(objectBytes) || objectBytes < 0) {
      throw new Error('high_water_body_invalid');
    }
    const nextTotalObjectBytes = totalObjectBytes + objectBytes;
    if (nextTotalObjectBytes > MAX_HIGH_WATER_SCAN_OBJECT_BYTES) {
      throw new Error('high_water_scan_bound_exceeded');
    }
    return nextTotalObjectBytes;
  }

  private assertChainEntry(
    context: DurableGenerationHighWaterTransportContextV1,
    entry: HighWaterLogEntryV1,
    sequence: number,
    previous: HighWaterLogEntryV1 | null,
  ): void {
    if (
      entry.logSequence !== sequence ||
      entry.checkpoint.orgId !== context.orgId ||
      entry.checkpoint.deploymentId !== context.deploymentId ||
      entry.checkpoint.releaseId !== context.releaseId ||
      entry.checkpoint.protectedSourceCommit !== context.protectedSourceCommit ||
      entry.checkpoint.eifDigest !== context.eifDigest ||
      entry.checkpoint.pcr0 !== context.pcr0 ||
      entry.checkpoint.bootRootDigest !== context.bootRootDigest ||
      entry.signerKeyId !== entry.checkpoint.signerKeyId
    ) {
      throw new Error('high_water_sequence_context_invalid');
    }
    if (previous === null) {
      if (entry.previousEntryDigest !== null || entry.checkpoint.predecessorDigest !== null) {
        throw new Error('high_water_sequence_gap');
      }
      return;
    }
    if (
      entry.previousEntryDigest !== previous.entryDigest ||
      entry.checkpoint.predecessorDigest !== previous.checkpoint.checkpointDigest ||
      entry.checkpoint.previousCheckpointDigest !== previous.checkpoint.checkpointDigest
    ) {
      throw new Error('high_water_sequence_fork');
    }
  }

  private verifyEntrySignature(entry: HighWaterLogEntryV1): void {
    const { entryDigest: _entryDigest, signature: _signature, ...unsigned } = entry;
    const unsignedBytes = encode(unsigned, rfc8949EncodeOptions);
    const entryDigest = createHash('sha256').update(unsignedBytes).digest('hex');
    if (entryDigest !== entry.entryDigest) throw new Error('high_water_entry_digest_mismatch');
    const signingBytes = Buffer.concat([
      Buffer.from('folklore.generation-high-water.v1\u0000', 'utf8'),
      Buffer.from(entryDigest, 'hex'),
    ]);
    if (!verify(null, signingBytes, this.signerKey, Buffer.from(entry.signature, 'base64'))) {
      throw new Error('high_water_signature_invalid');
    }
  }

  private sequenceFromKey(
    context: DurableGenerationHighWaterTransportContextV1,
    key: string,
  ): number {
    const prefix = this.sequencePrefix(context);
    if (!key.startsWith(prefix) || !key.endsWith('.cbor'))
      throw new Error('high_water_sequence_invalid');
    const sequenceText = key.slice(prefix.length, -'.cbor'.length);
    if (!/^\d{20}$/.test(sequenceText)) throw new Error('high_water_sequence_invalid');
    const sequence = Number(sequenceText);
    if (!Number.isSafeInteger(sequence) || sequence < 1)
      throw new Error('high_water_sequence_invalid');
    return sequence;
  }

  private objectKey(
    context: DurableGenerationHighWaterTransportContextV1,
    sequence: number,
  ): string {
    return `${this.sequencePrefix(context)}${sequence.toString().padStart(20, '0')}.cbor`;
  }

  private sequencePrefix(context: DurableGenerationHighWaterTransportContextV1): string {
    return `${this.options.config.objectPrefix}org/${context.orgId}/deployment/${context.deploymentId}/sequence/`;
  }

  private async readPointer(
    context: DurableGenerationHighWaterTransportContextV1,
  ): Promise<ReturnType<typeof highWaterPointerV1Schema.parse>> {
    const response = await this.options.dynamodb.send(
      new GetItemCommand({
        TableName: this.options.config.tableName,
        Key: { contextKey: { S: `${context.orgId}:${context.deploymentId}` } },
        ConsistentRead: true,
      }),
    );
    if (!response.Item) throw new Error('high_water_pointer_missing');
    const item = this.parsePointerAttributes(response.Item);
    const pointer = highWaterPointerV1Schema.parse(item);
    if (
      pointer.orgId !== context.orgId ||
      pointer.deploymentId !== context.deploymentId ||
      pointer.contextKey !== `${context.orgId}:${context.deploymentId}` ||
      pointer.pointerState !== 'healthy'
    ) {
      throw new Error('high_water_pointer_context_invalid');
    }
    return pointer;
  }

  private parsePointerAttributes(item: Record<string, unknown>): Record<string, unknown> {
    const keys = Object.keys(item).sort();
    const expected = [...POINTER_ATTRIBUTE_NAMES].sort();
    if (!isDeepStrictEqual(keys, expected)) throw new Error('high_water_pointer_invalid');
    const value = (name: string): Record<string, unknown> => {
      const attribute = item[name];
      if (typeof attribute !== 'object' || attribute === null) {
        throw new Error('high_water_pointer_invalid');
      }
      return attribute as Record<string, unknown>;
    };
    const stringValue = (name: string): string => {
      const attribute = value(name);
      if (typeof attribute.S !== 'string' || Object.keys(attribute).length !== 1) {
        throw new Error('high_water_pointer_invalid');
      }
      return attribute.S;
    };
    const numberValue = (name: string): number => {
      const attribute = value(name);
      if (typeof attribute.N !== 'string' || Object.keys(attribute).length !== 1) {
        throw new Error('high_water_pointer_invalid');
      }
      const parsed = Number(attribute.N);
      if (!Number.isSafeInteger(parsed)) throw new Error('high_water_pointer_invalid');
      return parsed;
    };
    const nullableNumberValue = (name: string): number | null => {
      const attribute = value(name);
      if (attribute.NULL === true && Object.keys(attribute).length === 1) return null;
      return numberValue(name);
    };
    return {
      pointerVersion: numberValue('pointerVersion'),
      contextKey: stringValue('contextKey'),
      orgId: stringValue('orgId'),
      deploymentId: stringValue('deploymentId'),
      logSequence: numberValue('logSequence'),
      entryDigest: stringValue('entryDigest'),
      checkpointDigest: stringValue('checkpointDigest'),
      objectKey: stringValue('objectKey'),
      objectVersionId: stringValue('objectVersionId'),
      pointerState: stringValue('pointerState'),
      updatedAtTrustedMs: nullableNumberValue('updatedAtTrustedMs'),
    };
  }

  private async readBoundedBody(body: unknown): Promise<Uint8Array> {
    if (body instanceof Uint8Array || Buffer.isBuffer(body)) {
      if (body.byteLength > MAX_HIGH_WATER_BODY_BYTES) throw new Error('high_water_body_oversized');
      return Uint8Array.from(body);
    }
    if (
      typeof body === 'object' &&
      body !== null &&
      'transformToByteArray' in body &&
      typeof body.transformToByteArray === 'function'
    ) {
      const bytes = await body.transformToByteArray();
      if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_HIGH_WATER_BODY_BYTES) {
        throw new Error('high_water_body_oversized');
      }
      return Uint8Array.from(bytes);
    }
    throw new Error('high_water_body_invalid');
  }

  private decodeCanonicalEntry(bytes: Uint8Array): HighWaterLogEntryV1 {
    try {
      const entry = highWaterLogEntryV1Schema.parse(decode(bytes));
      if (!isDeepStrictEqual(encode(entry, rfc8949EncodeOptions), bytes)) {
        throw new Error('high_water_body_noncanonical');
      }
      return entry;
    } catch (error: unknown) {
      if (error instanceof Error && error.message === 'high_water_body_noncanonical') throw error;
      throw new Error('high_water_body_invalid');
    }
  }
}
