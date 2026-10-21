import type {
  AttestedParameterRead,
  AttestedSsmParameterReader,
} from '../../attestation/AttestedSsmParameterReader.js';
import type { VerifiedBootManifest } from '../../attestation/BootManifestVerifier.js';

export type ProviderKeyManifest = Pick<
  VerifiedBootManifest,
  'awsAccountId' | 'awsRegion' | 'storageKeyArn' | 'enclaveOutputKeyKmsKeyArn'
>;

export interface AttestedProviderKeySpec {
  readonly parameterPath: string;
  readonly keyAlias: string;
  readonly keyShape: RegExp;
  readonly maxKeyBytes: number;
  readonly unavailable: () => Error;
}

export interface AttestedProviderKeyDeps {
  readonly reader: Pick<AttestedSsmParameterReader, 'read'>;
  readonly manifest: () => ProviderKeyManifest | undefined;
}

/** Reads one provider key through the attested reader, refusing the storage and output keys and any value of the wrong shape. */
export class AttestedProviderKeyReader {
  constructor(
    private readonly spec: AttestedProviderKeySpec,
    private readonly deps: AttestedProviderKeyDeps,
  ) {}

  async read(): Promise<Buffer> {
    const plaintext = await this.deps.reader.read(this.signedRead()).catch(() => {
      throw this.spec.unavailable();
    });
    const key = Buffer.from(plaintext).toString('utf8');
    plaintext.fill(0);
    if (
      plaintext.length === 0 ||
      plaintext.length > this.spec.maxKeyBytes ||
      !this.spec.keyShape.test(key)
    ) {
      throw this.spec.unavailable();
    }
    return Buffer.from(key, 'utf8');
  }

  private signedRead(): AttestedParameterRead {
    const manifest = this.deps.manifest();
    const outputKey = manifest?.enclaveOutputKeyKmsKeyArn;
    if (!manifest || !outputKey || !manifest.awsAccountId || !manifest.awsRegion) {
      throw this.spec.unavailable();
    }
    return {
      path: this.spec.parameterPath,
      awsAccountId: manifest.awsAccountId,
      awsRegion: manifest.awsRegion,
      keyId: `arn:aws:kms:${manifest.awsRegion}:${manifest.awsAccountId}:${this.spec.keyAlias}`,
      refusedKeyIds: [manifest.storageKeyArn, outputKey],
    };
  }
}
