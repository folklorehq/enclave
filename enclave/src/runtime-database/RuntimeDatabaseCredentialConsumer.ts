import { DecryptCommand } from '@aws-sdk/client-kms';
import { GetParameterCommand, type GetParameterCommandOutput } from '@aws-sdk/client-ssm';
import {
  createHash,
  constants,
  generateKeyPairSync,
  privateDecrypt,
  type KeyObject,
} from 'node:crypto';
import {
  runtimeDatabaseCredentialReceiptSchema,
  runtimeDatabaseConfigSchema,
  runtimeDatabaseBinding,
  runtimeDatabaseBindingSchema,
  encodeRuntimeDatabaseBinding,
  type RuntimeDatabaseBinding,
  type RuntimeDatabaseConfig,
  type RuntimeDatabaseCredentialReceipt,
} from '@folklore/contracts/enclave-attestation';
import { z } from 'zod';

const MAX_PARAMETER_BYTES = 131_072;
const MAX_CIPHERTEXT_BYTES = 65_536;

const runtimeEnvelopeSchema = z
  .object({
    version: z.literal(1),
    binding: runtimeDatabaseBindingSchema,
    ciphertext: z
      .string()
      .min(4)
      .max(Math.ceil((MAX_CIPHERTEXT_BYTES * 4) / 3) + 4),
  })
  .strict();

const credentialSchema = z
  .object({
    username: z.literal('folklore_app'),
    password: z.string().min(1).max(4_096),
  })
  .strict();

export type RuntimeDatabaseCredentialErrorCode =
  | 'runtime_database_config_invalid'
  | 'runtime_database_parameter_unavailable'
  | 'runtime_database_envelope_invalid'
  | 'runtime_database_kms_response_invalid'
  | 'runtime_database_credential_invalid'
  | 'runtime_database_readiness_failed';

export class RuntimeDatabaseCredentialError extends Error {
  constructor(code: RuntimeDatabaseCredentialErrorCode) {
    super(code);
    this.name = 'RuntimeDatabaseCredentialError';
  }
}

export interface RuntimeDatabaseParameter {
  name?: string;
  version?: number;
  value?: string;
}

export interface RuntimeDatabaseParameterPort {
  getExact(input: { name: string; version: number }): Promise<RuntimeDatabaseParameter>;
}

export interface RuntimeDatabaseConnection {
  close(): Promise<void>;
}

export interface RecipientDecryptInput {
  ciphertext: Buffer;
  keyId: string;
  encryptionContext: RuntimeDatabaseBinding;
}

export interface RuntimeDatabaseRecipientDecryptor {
  decryptForRecipient(input: RecipientDecryptInput): Promise<Buffer>;
}

export interface RuntimeDatabaseReadinessResult {
  role: 'folklore_app';
  rls: 'enforced';
  apiHealth: 'healthy';
}

export interface RuntimeDatabaseReadinessPort<TDatabase extends RuntimeDatabaseConnection> {
  verify(
    database: TDatabase,
    config: RuntimeDatabaseConfig,
    probeOrgId: string,
  ): Promise<RuntimeDatabaseReadinessResult>;
}

interface RuntimeDatabaseCredentialConsumerDeps<TDatabase extends RuntimeDatabaseConnection> {
  parameters: RuntimeDatabaseParameterPort;
  recipientDecryptor: RuntimeDatabaseRecipientDecryptor;
  createDatabase(input: { url: string; sslServerName: string }): TDatabase;
  readiness: RuntimeDatabaseReadinessPort<TDatabase>;
}

export interface ConsumedRuntimeDatabaseCredential<TDatabase extends RuntimeDatabaseConnection> {
  database: TDatabase;
  receipt: RuntimeDatabaseCredentialReceipt;
}

export class RuntimeDatabaseCredentialConsumer<TDatabase extends RuntimeDatabaseConnection> {
  constructor(private readonly deps: RuntimeDatabaseCredentialConsumerDeps<TDatabase>) {}

  async consume(
    input: RuntimeDatabaseConfig,
    probeOrgId: string,
  ): Promise<ConsumedRuntimeDatabaseCredential<TDatabase>> {
    const parsedConfig = runtimeDatabaseConfigSchema.safeParse(input);
    if (!parsedConfig.success) throw this.failure('runtime_database_config_invalid');
    const config = parsedConfig.data;
    const parameter = await this.readParameter(config);
    if (this.hash(Buffer.from(parameter.value, 'utf8')) !== config.envelope.envelopeSha256) {
      throw this.failure('runtime_database_envelope_invalid');
    }
    const envelope = this.parseEnvelope(parameter.value, config);
    const binding = runtimeDatabaseBinding(config);
    const plaintext = await this.decrypt(envelope.ciphertext, config, binding);
    let database: TDatabase | undefined;
    try {
      const credential = this.parseCredential(plaintext);
      database = this.deps.createDatabase({
        url: this.databaseUrl(config, credential.password),
        sslServerName: config.endpoint.host,
      });
      const readiness = await this.deps.readiness.verify(database, config, probeOrgId);
      return {
        database,
        receipt: runtimeDatabaseCredentialReceiptSchema.parse({
          version: 1,
          envelopeSha256: this.hash(parameter.value),
          bindingSha256: this.hash(encodeRuntimeDatabaseBinding(config)),
          parameterVersion: config.envelope.parameterVersion,
          ...readiness,
        }),
      };
    } catch (error: unknown) {
      await database?.close().catch(() => undefined);
      if (error instanceof RuntimeDatabaseCredentialError) throw error;
      throw this.failure('runtime_database_readiness_failed');
    } finally {
      plaintext.fill(0);
    }
  }

  private async readParameter(
    config: RuntimeDatabaseConfig,
  ): Promise<Required<RuntimeDatabaseParameter>> {
    let parameter: RuntimeDatabaseParameter;
    try {
      parameter = await this.deps.parameters.getExact({
        name: config.envelope.parameterPath,
        version: config.envelope.parameterVersion,
      });
    } catch {
      throw this.failure('runtime_database_parameter_unavailable');
    }
    if (
      parameter.name !== config.envelope.parameterPath ||
      parameter.version !== config.envelope.parameterVersion ||
      typeof parameter.value !== 'string' ||
      Buffer.byteLength(parameter.value, 'utf8') > MAX_PARAMETER_BYTES
    ) {
      throw this.failure('runtime_database_envelope_invalid');
    }
    return { name: parameter.name, version: parameter.version, value: parameter.value };
  }

  private parseEnvelope(value: string, config: RuntimeDatabaseConfig): { ciphertext: Buffer } {
    let raw: unknown;
    try {
      raw = JSON.parse(value);
    } catch {
      throw this.failure('runtime_database_envelope_invalid');
    }
    const parsed = runtimeEnvelopeSchema.safeParse(raw);
    if (
      !parsed.success ||
      JSON.stringify(parsed.data.binding) !== encodeRuntimeDatabaseBinding(config)
    ) {
      throw this.failure('runtime_database_envelope_invalid');
    }
    const ciphertext = Buffer.from(parsed.data.ciphertext, 'base64');
    if (
      ciphertext.byteLength === 0 ||
      ciphertext.byteLength > MAX_CIPHERTEXT_BYTES ||
      ciphertext.toString('base64') !== parsed.data.ciphertext
    ) {
      throw this.failure('runtime_database_envelope_invalid');
    }
    return { ciphertext };
  }

  private async decrypt(
    ciphertext: Buffer,
    config: RuntimeDatabaseConfig,
    encryptionContext: RuntimeDatabaseBinding,
  ): Promise<Buffer> {
    try {
      return await this.deps.recipientDecryptor.decryptForRecipient({
        ciphertext,
        keyId: config.envelope.runtimeEnvelopeKeyArn,
        encryptionContext,
      });
    } catch (error: unknown) {
      if (error instanceof RuntimeDatabaseCredentialError) throw error;
      throw this.failure('runtime_database_kms_response_invalid');
    }
  }

  private parseCredential(plaintext: Buffer): z.infer<typeof credentialSchema> {
    let raw: unknown;
    try {
      raw = JSON.parse(plaintext.toString('utf8'));
    } catch {
      throw this.failure('runtime_database_credential_invalid');
    }
    const credential = credentialSchema.safeParse(raw);
    if (!credential.success) throw this.failure('runtime_database_credential_invalid');
    return credential.data;
  }

  private databaseUrl(config: RuntimeDatabaseConfig, password: string): string {
    return `postgresql://folklore_app:${encodeURIComponent(password)}@127.0.0.1:${config.endpoint.port}/${encodeURIComponent(config.database)}?sslmode=verify-full`;
  }

  private hash(value: string | Uint8Array): string {
    return createHash('sha256').update(value).digest('hex');
  }

  private failure(code: RuntimeDatabaseCredentialErrorCode): RuntimeDatabaseCredentialError {
    return new RuntimeDatabaseCredentialError(code);
  }
}

interface KmsDecryptClient {
  send(command: DecryptCommand): Promise<{
    Plaintext?: Uint8Array;
    CiphertextForRecipient?: Uint8Array;
  }>;
}

type AttestationDocumentProvider = (publicKey: Uint8Array) => Uint8Array;

export class KmsRecipientDecryptor implements RuntimeDatabaseRecipientDecryptor {
  constructor(
    private readonly client: KmsDecryptClient,
    private readonly attestationDocument: AttestationDocumentProvider,
  ) {}

  async decryptForRecipient(input: RecipientDecryptInput): Promise<Buffer> {
    const keyPair = generateKeyPairSync('rsa', { modulusLength: 2_048 });
    const publicKey = Buffer.from(keyPair.publicKey.export({ type: 'spki', format: 'der' }));
    const response = await this.client.send(
      new DecryptCommand({
        KeyId: input.keyId,
        CiphertextBlob: input.ciphertext,
        EncryptionContext: Object.fromEntries(Object.entries(input.encryptionContext)),
        Recipient: {
          KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256',
          AttestationDocument: this.attestationDocument(publicKey),
        },
      }),
    );
    if (response.Plaintext !== undefined || !response.CiphertextForRecipient?.byteLength) {
      throw new RuntimeDatabaseCredentialError('runtime_database_kms_response_invalid');
    }
    return this.openRecipientCiphertext(keyPair.privateKey, response.CiphertextForRecipient);
  }

  private openRecipientCiphertext(privateKey: KeyObject, ciphertext: Uint8Array): Buffer {
    try {
      return privateDecrypt(
        {
          key: privateKey,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        Buffer.from(ciphertext),
      );
    } catch {
      throw new RuntimeDatabaseCredentialError('runtime_database_kms_response_invalid');
    }
  }
}

interface SsmParameterClient {
  send(command: GetParameterCommand): Promise<GetParameterCommandOutput>;
}

export class SsmRuntimeDatabaseParameters implements RuntimeDatabaseParameterPort {
  constructor(private readonly client: SsmParameterClient) {}

  async getExact(input: { name: string; version: number }): Promise<RuntimeDatabaseParameter> {
    const response = await this.client.send(
      new GetParameterCommand({
        Name: `${input.name}:${input.version}`,
        WithDecryption: false,
      }),
    );
    return {
      name: response.Parameter?.Name,
      version: response.Parameter?.Version,
      value: response.Parameter?.Value,
    };
  }
}
