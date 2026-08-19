import { timingSafeEqual } from 'node:crypto';
import { PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import AWS from 'aws-sdk';
import { KmsKeyringNode } from '@aws-crypto/client-node';
import { generateMasterKey } from '../sealing/keygen.js';
import { awsV2ClientTransport } from '../aws/aws-transport.js';
import { createRecipientKmsClient } from '../aws/RecipientKmsClient.js';
import {
  decryptRecipientCiphertextWithKeyId,
  sealMasterKey,
  unsealMasterKey,
} from '../sealing/seal.js';
import { readSealedBlob, writeSealedBlob } from '../sealing/sealed-blob-store.js';
import { assertRecoveryConfigured, sealRecoveryMnemonic } from '../sealing/recovery.js';
import { HnswStore } from '../hnsw/index.js';
import { Pipeline } from '../pipeline/index.js';
import {
  EnclaveCrypto,
  singleVersionSealedContentKeyring,
  type SealedContentKeyringConfig,
} from '../crypto/esdk.js';
import { inferenceModel, phalaInference } from '../inference/phala.js';
import {
  CachedInference,
  LLM_CACHE_PROMPT_VERSION,
  type InferenceModel,
} from '../inference/CachedInference.js';
import { S3LlmCache } from '../inference/S3LlmCache.js';
import { TenantContext } from './tenant-context.js';

export interface TenantIdentity {
  tenantId: string;
  deploymentId?: string;
  tenantDeploymentId?: string;
  /** Master CMK — seals/unseals the master blob only, never content. */
  kmsKeyId: string;
  activeStorageKeyVersion: number;
  storageKeyHistory: readonly { version: number; storageKeyId: string }[];
  recoveryPubkey: string;
  signedRecoveryPubkey?: string;
  sealedBlobBucket?: string;
  rawPayloadsBucket?: string;
  processedBucket?: string;
}

export type SealMasterKeyFn = (
  masterKey: Buffer,
  kmsKeyId: string,
  tenantId: string,
) => Promise<Buffer>;

export type UnsealMasterKeyFn = (
  blob: Buffer,
  kmsKeyId: string,
  tenantId: string,
) => Promise<Buffer>;

export interface TenantContextFactoryDeps {
  s3: S3Client;
  region: string;
  /** From the root-signed boot manifest (audit F2), read late: it is verified after this is built. */
  signedRecoveryPubkey?: () => string | undefined;
  /** The tenant's storage key ARN from the verified boot manifest; the identity's env value must agree. */
  signedStorageKeyArn?: () => string | undefined;
  /** Test seam: replaces the AWS SDK v2 KMS client constructor the ESDK keyring uses. */
  kmsClientProvider?: (region?: string) => AWS.KMS;
  sealedBlobBucket: string;
  processedOutputsBucket: string;
  sealMasterKey?: SealMasterKeyFn;
  unsealMasterKey?: UnsealMasterKeyFn;
}

const MASTER_KEY_BYTES = 32;
const VERIFIED_BOOT_PROOF_ERROR = 'verified boot proof failed';

// Builds one tenant's isolated context (single-CMK keyring, unsealed master key, per-org HNSW,
// pipeline). One factory serves the whole enclave; Stage 1 builds exactly one context, but the
// per-tenant boot/keyring wiring is already parameterized so Stage 2 can build N (design §2.3).
export class TenantContextFactory {
  constructor(private readonly deps: TenantContextFactoryDeps) {}

  async build(identity: TenantIdentity): Promise<TenantContext> {
    const sealedBlobBucket = this.resolveBucket(
      identity.sealedBlobBucket ?? '',
      this.deps.sealedBlobBucket,
    );
    const processedBucket = this.resolveBucket(
      identity.processedBucket ?? '',
      this.deps.processedOutputsBucket,
    );
    const sealedContentKeyrings = this.buildSealedContentKeyrings(identity);
    const keyring = sealedContentKeyrings.keyrings.get(sealedContentKeyrings.activeVersion);
    if (!keyring) throw new Error('sealed content keyring configuration is invalid');
    const masterKey = await this.bootMasterKey(identity);
    try {
      const hnsw = await HnswStore.load(this.deps.s3, keyring, processedBucket, identity.tenantId);
      const pipeline = new Pipeline(
        hnsw,
        this.deps.s3,
        keyring,
        processedBucket,
        identity.tenantId,
        this.buildInference(keyring, identity.tenantId, processedBucket),
      );
      return new TenantContext(
        identity.tenantId,
        identity.kmsKeyId,
        keyring,
        masterKey,
        hnsw,
        pipeline,
        sealedContentKeyrings,
        sealedBlobBucket,
        identity.rawPayloadsBucket ?? '',
        processedBucket,
        identity.deploymentId ?? '',
        identity.tenantDeploymentId,
      );
    } catch (error) {
      masterKey.fill(0);
      throw error;
    }
  }

  private buildInference(
    keyring: KmsKeyringNode,
    tenantId: string,
    processedBucket: string,
  ): InferenceModel {
    const cache = new S3LlmCache({
      s3: this.deps.s3,
      crypto: new EnclaveCrypto(keyring, singleVersionSealedContentKeyring(keyring)),
      bucket: processedBucket,
      orgId: tenantId,
    });
    return new CachedInference(phalaInference, cache, {
      embedModel: inferenceModel('embed'),
      generateModel: inferenceModel('generate'),
      critiqueModel: inferenceModel('critique'),
      promptVersion: LLM_CACHE_PROMPT_VERSION,
    });
  }

  // The content keyring is built from the tenant's STORAGE key, never the master key: the master
  // key's Decrypt is attestation-gated, and an IAM decrypt on it would be a non-attested unseal
  // path. The dedicated box's storage key arrives in the SIGNED boot manifest; the pool box's in
  // the assignment manifest. Either may be absent only if the other is present, and the two must
  // agree — a mismatch or a total absence refuses the boot.
  private buildSealedContentKeyrings(identity: TenantIdentity): SealedContentKeyringConfig {
    const history = identity.storageKeyHistory.map((entry) => ({
      version: entry.version,
      storageKeyId: entry.storageKeyId.trim(),
    }));
    if (history.some((entry) => entry.storageKeyId === identity.kmsKeyId.trim())) {
      throw new Error('storage key must differ from the master CMK');
    }
    if (
      history.length === 0 ||
      history.some(
        (entry, index) =>
          !Number.isSafeInteger(entry.version) ||
          entry.version < 1 ||
          entry.storageKeyId.length === 0 ||
          (index > 0 && history[index - 1]!.version >= entry.version),
      ) ||
      new Set(history.map((entry) => entry.storageKeyId)).size !== history.length
    ) {
      throw new Error('storage key history is invalid');
    }
    const active = history.find((entry) => entry.version === identity.activeStorageKeyVersion);
    if (!active) throw new Error('active storage key version is not configured');
    const keyrings = new Map(
      history.map((entry) => [entry.version, this.buildKeyring(entry.storageKeyId)] as const),
    );
    this.assertSignedStorageKey(identity, active.storageKeyId);
    return { activeVersion: identity.activeStorageKeyVersion, keyrings };
  }

  private assertSignedStorageKey(identity: TenantIdentity, activeStorageKeyId: string): void {
    const signedKey = this.deps.signedStorageKeyArn?.()?.trim() ?? '';
    if (signedKey && activeStorageKeyId !== signedKey) {
      throw new Error('refusing boot: storage key disagrees with the signed boot manifest');
    }
    if (!activeStorageKeyId) {
      throw new Error(
        'refusing boot: no storage key configured (content keyring must never fall back to the master CMK)',
      );
    }
    // Last line: even if a producer or schema regression let an equal key through, never build the
    // content keyring on the master key — its Decrypt is attestation-gated, so content would seal
    // write-only and be unrecoverable.
    if (activeStorageKeyId === identity.kmsKeyId.trim()) {
      throw new Error('refusing boot: storage key must differ from the master CMK');
    }
  }

  private buildKeyring(kmsKeyId: string): KmsKeyringNode {
    const provider =
      this.deps.kmsClientProvider ??
      ((r?: string) =>
        new AWS.KMS({
          region: r || this.deps.region,
          ...awsV2ClientTransport(),
        }));
    return new KmsKeyringNode({
      generatorKeyId: kmsKeyId,
      clientProvider: (region?: string) =>
        createRecipientKmsClient(
          provider(region || this.deps.region),
          ({ ciphertext, keyId, encryptionContext }) =>
            decryptRecipientCiphertextWithKeyId(ciphertext, keyId, encryptionContext),
          kmsKeyId,
        ),
    });
  }

  private async bootMasterKey(identity: TenantIdentity): Promise<Buffer> {
    const sealedBlobBucket = this.resolveBucket(
      identity.sealedBlobBucket ?? '',
      this.deps.sealedBlobBucket,
    );
    const sealedBlob = await readSealedBlob(this.deps.s3, sealedBlobBucket, identity.tenantId);

    if (sealedBlob) {
      return this.unsealExistingMasterKey(sealedBlob, identity);
    }

    return this.firstBoot(identity);
  }

  private async firstBoot(identity: TenantIdentity): Promise<Buffer> {
    const sealedBlobBucket = this.resolveBucket(
      identity.sealedBlobBucket ?? '',
      this.deps.sealedBlobBucket,
    );
    const recoveryKey = assertRecoveryConfigured(
      identity.recoveryPubkey,
      identity.signedRecoveryPubkey ?? this.deps.signedRecoveryPubkey?.(),
    );
    const masterKey = generateMasterKey();
    try {
      const recoveryBox = sealRecoveryMnemonic(masterKey, recoveryKey);
      await this.deps.s3.send(
        new PutObjectCommand({
          Bucket: sealedBlobBucket,
          Key: this.recoveryBlobKey(identity.tenantId),
          Body: JSON.stringify(recoveryBox),
          ContentType: 'application/json',
        }),
      );

      const blob = await this.seal(masterKey, identity);
      await this.verifyFirstBootRoundTrip(blob, masterKey, identity);
      await writeSealedBlob(this.deps.s3, sealedBlobBucket, identity.tenantId, blob);
      return masterKey;
    } catch (error) {
      masterKey.fill(0);
      throw error;
    }
  }

  private resolveBucket(identityBucket: string, fallbackBucket: string): string {
    const bucket = identityBucket.trim() || fallbackBucket.trim();
    if (!bucket) throw new Error('tenant storage bucket is not configured');
    return bucket;
  }

  private async seal(masterKey: Buffer, identity: TenantIdentity): Promise<Buffer> {
    return (this.deps.sealMasterKey ?? sealMasterKey)(
      masterKey,
      identity.kmsKeyId,
      identity.tenantId,
    );
  }

  private async verifyFirstBootRoundTrip(
    blob: Buffer,
    masterKey: Buffer,
    identity: TenantIdentity,
  ): Promise<void> {
    let roundTripMasterKey: Buffer | undefined;
    try {
      const unsealedMasterKey = await (this.deps.unsealMasterKey ?? unsealMasterKey)(
        blob,
        identity.kmsKeyId,
        identity.tenantId,
      );
      if (!Buffer.isBuffer(unsealedMasterKey)) throw new Error(VERIFIED_BOOT_PROOF_ERROR);
      roundTripMasterKey = unsealedMasterKey;
      if (
        roundTripMasterKey.length !== MASTER_KEY_BYTES ||
        !timingSafeEqual(roundTripMasterKey, masterKey)
      ) {
        throw new Error(VERIFIED_BOOT_PROOF_ERROR);
      }
    } catch {
      masterKey.fill(0);
      throw new Error(VERIFIED_BOOT_PROOF_ERROR);
    } finally {
      roundTripMasterKey?.fill(0);
    }
  }

  private async unsealExistingMasterKey(blob: Buffer, identity: TenantIdentity): Promise<Buffer> {
    let masterKey: Buffer | undefined;
    try {
      masterKey = await (this.deps.unsealMasterKey ?? unsealMasterKey)(
        blob,
        identity.kmsKeyId,
        identity.tenantId,
      );
      if (masterKey.length !== MASTER_KEY_BYTES) throw new Error(VERIFIED_BOOT_PROOF_ERROR);
      return masterKey;
    } catch {
      masterKey?.fill(0);
      throw new Error(VERIFIED_BOOT_PROOF_ERROR);
    }
  }

  private recoveryBlobKey(tenantId: string): string {
    return `recovery/${tenantId}/mnemonic.enc`;
  }
}
