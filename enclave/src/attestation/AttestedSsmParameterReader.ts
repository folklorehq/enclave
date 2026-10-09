import type {
  AttestedSecretDecryptorPort,
  SsmParameterValuePort,
} from './BootManifestSecretLoader.js';
import { readFailureCode } from './read-failure-code.js';

export interface AttestedParameterReadErrors {
  readonly missing: string;
  readonly accessDenied: string;
  readonly identity: string;
  readonly version: string;
  readonly value: string;
  readonly decrypt: string;
}

export interface AttestedParameterRead {
  readonly path: string;
  readonly awsAccountId: string;
  readonly awsRegion: string;
  readonly version?: number;
  readonly keyId?: string;
  readonly refusedKeyIds?: readonly string[];
}

/** Reads a SecureString as ciphertext and opens it only through an attested KMS Recipient. */
export class AttestedSsmParameterReader {
  constructor(
    private readonly ssm: SsmParameterValuePort,
    private readonly decryptor: AttestedSecretDecryptorPort,
    private readonly errors: AttestedParameterReadErrors,
  ) {}

  async read(input: AttestedParameterRead): Promise<Buffer> {
    const response = await this.fetch(input);
    if (response.name !== input.path) throw new Error(this.errors.identity);
    if (input.version !== undefined && response.version !== input.version) {
      throw new Error(this.errors.version);
    }
    return this.decrypt(this.ciphertext(response.value), input);
  }

  private async fetch(
    input: AttestedParameterRead,
  ): ReturnType<SsmParameterValuePort['getParameter']> {
    try {
      return await this.ssm.getParameter({
        name: input.path,
        ...(input.version === undefined ? {} : { version: input.version }),
        withDecryption: false,
      });
    } catch (error) {
      throw new Error(readFailureCode(error, this.errors.missing, this.errors.accessDenied));
    }
  }

  private ciphertext(value: unknown): Buffer {
    if (typeof value !== 'string' || value.length === 0) throw new Error(this.errors.value);
    const ciphertext = Buffer.from(value, 'base64');
    if (ciphertext.length === 0 || ciphertext.toString('base64') !== value) {
      throw new Error(this.errors.value);
    }
    return ciphertext;
  }

  private async decrypt(ciphertext: Buffer, input: AttestedParameterRead): Promise<Buffer> {
    try {
      return await this.decryptor.decryptForRecipient({
        ciphertext,
        ...(input.keyId === undefined ? {} : { keyId: input.keyId }),
        ...(input.refusedKeyIds === undefined ? {} : { refusedKeyIds: input.refusedKeyIds }),
        encryptionContext: {
          PARAMETER_ARN: `arn:aws:ssm:${input.awsRegion}:${input.awsAccountId}:parameter${input.path}`,
        },
      });
    } catch (error) {
      throw new Error(readFailureCode(error, this.errors.decrypt));
    }
  }
}
