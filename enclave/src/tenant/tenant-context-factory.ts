import { GetObjectCommand, NoSuchKey, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { PutParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';
import { KMSClient } from '@aws-sdk/client-kms';
import { KmsKeyringNode } from '@aws-crypto/client-node';
import { deriveIngestKeypair, generateMasterKey } from '../sealing/keygen.js';
import { sealMasterKey, unsealMasterKey } from '../sealing/seal.js';
import { assertRecoveryConfigured, sealRecoveryMnemonic } from '../sealing/recovery.js';
import { HnswStore } from '../hnsw/index.js';
import { Pipeline } from '../pipeline/index.js';
import { EnclaveCrypto } from '../crypto/esdk.js';
import { EMBED_MODEL, GENERATE_MODEL, phalaInference } from '../inference/phala.js';
import {
  CachedInference,
  LLM_CACHE_PROMPT_VERSION,
  type InferenceModel,
} from '../inference/cached-inference.js';
import { S3LlmCache } from '../inference/s3-llm-cache.js';
import { TenantContext } from './tenant-context.js';

export interface TenantIdentity {
  tenantId: string;
  kmsKeyId: string;
  recoveryPubkey: string;
}

export interface TenantContextFactoryDeps {
  s3: S3Client;
  ssm: SSMClient;
  region: string;
  proxyEndpoint: string;
  sealedBlobBucket: string;
  processedOutputsBucket: string;
}

// Builds one tenant's isolated context (single-CMK keyring, unsealed master key, per-org HNSW,
// pipeline). One factory serves the whole enclave; Stage 1 builds exactly one context, but the
// per-tenant boot/keyring wiring is already parameterized so Stage 2 can build N (design §2.3).
export class TenantContextFactory {
  constructor(private readonly deps: TenantContextFactoryDeps) {}

  async build(identity: TenantIdentity): Promise<TenantContext> {
    const keyring = this.buildKeyring(identity.kmsKeyId);
    const masterKey = await this.bootMasterKey(identity);
    const hnsw = await HnswStore.load(
      this.deps.s3,
      keyring,
      this.deps.processedOutputsBucket,
      identity.tenantId,
    );
    const pipeline = new Pipeline(
      hnsw,
      this.deps.s3,
      keyring,
      this.deps.processedOutputsBucket,
      identity.tenantId,
      this.buildInference(keyring, identity.tenantId),
    );
    return new TenantContext(
      identity.tenantId,
      identity.kmsKeyId,
      keyring,
      masterKey,
      hnsw,
      pipeline,
    );
  }

  private buildInference(keyring: KmsKeyringNode, tenantId: string): InferenceModel {
    const cache = new S3LlmCache({
      s3: this.deps.s3,
      crypto: new EnclaveCrypto(keyring),
      bucket: this.deps.processedOutputsBucket,
      orgId: tenantId,
    });
    return new CachedInference(phalaInference, cache, {
      embedModel: EMBED_MODEL,
      generateModel: GENERATE_MODEL,
      promptVersion: LLM_CACHE_PROMPT_VERSION,
    });
  }

  private buildKeyring(kmsKeyId: string): KmsKeyringNode {
    return new KmsKeyringNode({
      generatorKeyId: kmsKeyId,
      clientProvider: (r?: string) =>
        new KMSClient({
          region: r ?? this.deps.region,
          endpoint: this.deps.proxyEndpoint,
        }) as never,
    });
  }

  private async bootMasterKey(identity: TenantIdentity): Promise<Buffer> {
    const sealedBlob = await this.readSealedBlob(this.sealedBlobKey(identity.tenantId));

    if (sealedBlob) {
      console.log('unsealing master key via KMS');
      const masterKey = await unsealMasterKey(sealedBlob, identity.kmsKeyId, identity.tenantId);
      console.log('unseal ok');
      return masterKey;
    }

    return this.firstBoot(identity);
  }

  private async readSealedBlob(key: string): Promise<Buffer | null> {
    try {
      const obj = await this.deps.s3.send(
        new GetObjectCommand({ Bucket: this.deps.sealedBlobBucket, Key: key }),
      );
      return Buffer.from(await obj.Body!.transformToByteArray());
    } catch (err) {
      if (!(err instanceof NoSuchKey)) throw err;
      return null;
    }
  }

  private async firstBoot(identity: TenantIdentity): Promise<Buffer> {
    console.log('first boot — generating master key');
    // Fail closed before generating a key we could never let the customer recover (ADL #55).
    const recoveryKey = assertRecoveryConfigured(identity.recoveryPubkey);
    const masterKey = generateMasterKey();

    // Store only ciphertext the customer alone can open; write it before persisting the master
    // blob so a recovery-store failure leaves no ingestible tenant behind.
    const recoveryBox = sealRecoveryMnemonic(masterKey, recoveryKey);
    await this.deps.s3.send(
      new PutObjectCommand({
        Bucket: this.deps.sealedBlobBucket,
        Key: this.recoveryBlobKey(identity.tenantId),
        Body: JSON.stringify(recoveryBox),
        ContentType: 'application/json',
      }),
    );

    const blob = await sealMasterKey(masterKey, identity.kmsKeyId, identity.tenantId);
    await this.deps.s3.send(
      new PutObjectCommand({
        Bucket: this.deps.sealedBlobBucket,
        Key: this.sealedBlobKey(identity.tenantId),
        Body: blob,
      }),
    );

    const { publicKeyRaw } = deriveIngestKeypair(masterKey);
    await this.deps.ssm.send(
      new PutParameterCommand({
        Name: this.ingestKeySsmPath(identity.tenantId),
        Value: publicKeyRaw.toString('hex'),
        Type: 'String',
        Overwrite: true,
      }),
    );

    console.log('FIRST_BOOT', { tenant: identity.tenantId });
    return masterKey;
  }

  private sealedBlobKey(tenantId: string): string {
    return `sealed-keys/${tenantId}/master.blob`;
  }

  private recoveryBlobKey(tenantId: string): string {
    return `recovery/${tenantId}/mnemonic.enc`;
  }

  private ingestKeySsmPath(tenantId: string): string {
    return `/folklore/${tenantId}/ingest-public-key`;
  }
}
