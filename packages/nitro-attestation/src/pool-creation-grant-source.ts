import {
  generalAdmissionPolicyGrantObjectKey,
  type SignedGeneralAdmissionPolicyGrantV1,
} from '@folklore/contracts';
import { z } from 'zod';
import {
  GeneralAdmissionPolicyGrantReader,
  type GeneralAdmissionPolicyGrantAuthorityKeyPort,
  type GeneralAdmissionPolicyGrantObjectStorePort,
} from './GeneralAdmissionPolicyGrantReader.js';

/** The immutable-custody pins a deployment renders for the grant it is configured to read. */
export const GENERAL_ADMISSION_GRANT_PIN_ENV = {
  bucket: 'GENERAL_ADMISSION_GRANT_BUCKET',
  key: 'GENERAL_ADMISSION_GRANT_KEY',
  versionId: 'GENERAL_ADMISSION_GRANT_VERSION_ID',
  objectDigest: 'GENERAL_ADMISSION_GRANT_OBJECT_DIGEST',
  storageKeyId: 'GENERAL_ADMISSION_GRANT_STORAGE_KMS_KEY_ARN',
  authorityKeyArn: 'GENERAL_ADMISSION_GRANT_AUTHORITY_KEY_ARN',
  authorityKeyId: 'GENERAL_ADMISSION_GRANT_AUTHORITY_KEY_ID',
  authorityPublicKeySpkiSha256: 'GENERAL_ADMISSION_GRANT_AUTHORITY_SPKI_SHA256',
  authorityEpoch: 'GENERAL_ADMISSION_GRANT_AUTHORITY_EPOCH',
} as const;

type PinField = keyof typeof GENERAL_ADMISSION_GRANT_PIN_ENV;

export type GeneralAdmissionGrantPinCode =
  | 'general_admission_grant_pin_missing'
  | 'general_admission_grant_pin_malformed'
  | 'general_admission_grant_pin_inconsistent';

/** A pin refusal names the variables it refused, so a startup failure is actionable without a dump. */
export class GeneralAdmissionGrantPinError extends Error {
  constructor(
    readonly code: GeneralAdmissionGrantPinCode,
    readonly variables: readonly string[],
  ) {
    super(`${code}: ${variables.join(', ')}`);
    this.name = 'GeneralAdmissionGrantPinError';
  }
}

export interface GeneralAdmissionGrantScope {
  readonly environment: string;
  readonly awsAccountId: string;
  readonly awsRegion: string;
}

export interface GeneralAdmissionGrantPins {
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly objectDigest: string;
  readonly storageKeyId: string;
  readonly authorityKeyArn: string;
  readonly authorityKeyId: string;
  readonly authorityPublicKeySpkiSha256: string;
  readonly authorityEpoch: number;
}

const s3BucketSchema = z
  .string()
  .min(3)
  .max(63)
  .regex(/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/);
const opaqueIdSchema = z
  .string()
  .min(1)
  .max(1_024)
  .regex(/^[^\s]+$/);
const digestSchema = z.string().regex(/^[0-9a-f]{64}$/);
const kmsKeyArnSchema = z
  .string()
  .regex(
    /^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  );
const kmsKeyIdSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
const authorityEpochSchema = z
  .string()
  .regex(/^[1-9]\d{0,9}$/)
  .transform((value) => Number(value));

const pinsSchema = z
  .object({
    bucket: s3BucketSchema,
    key: opaqueIdSchema,
    versionId: opaqueIdSchema,
    objectDigest: digestSchema,
    storageKeyId: kmsKeyArnSchema,
    authorityKeyArn: kmsKeyArnSchema,
    authorityKeyId: kmsKeyIdSchema,
    authorityPublicKeySpkiSha256: digestSchema,
    authorityEpoch: authorityEpochSchema,
  })
  .strict();

/** Parse the required pins, or refuse with the variables at fault. Never reads a value at runtime. */
export function parseGeneralAdmissionGrantPins(input: {
  readonly env: NodeJS.ProcessEnv;
  readonly scope: GeneralAdmissionGrantScope;
}): GeneralAdmissionGrantPins {
  const fields = Object.keys(GENERAL_ADMISSION_GRANT_PIN_ENV) as readonly PinField[];
  const missing = fields
    .filter((field) => {
      const value = input.env[GENERAL_ADMISSION_GRANT_PIN_ENV[field]];
      return value === undefined || value === '';
    })
    .map((field) => GENERAL_ADMISSION_GRANT_PIN_ENV[field]);
  if (missing.length > 0) {
    throw new GeneralAdmissionGrantPinError('general_admission_grant_pin_missing', missing);
  }
  const raw = Object.fromEntries(
    fields.map((field) => [field, input.env[GENERAL_ADMISSION_GRANT_PIN_ENV[field]]]),
  );
  const parsed = pinsSchema.safeParse(raw);
  if (!parsed.success) {
    const malformed = [
      ...new Set(
        parsed.error.issues.map(
          (issue) => GENERAL_ADMISSION_GRANT_PIN_ENV[issue.path[0] as PinField],
        ),
      ),
    ];
    throw new GeneralAdmissionGrantPinError('general_admission_grant_pin_malformed', malformed);
  }
  assertPinsAgree(parsed.data, input.scope);
  return parsed.data;
}

function assertPinsAgree(pins: GeneralAdmissionGrantPins, scope: GeneralAdmissionGrantScope): void {
  const inconsistent: string[] = [];
  const arn = pins.authorityKeyArn.split(':');
  if (!pins.authorityKeyArn.endsWith(`:key/${pins.authorityKeyId}`)) {
    inconsistent.push(GENERAL_ADMISSION_GRANT_PIN_ENV.authorityKeyId);
  }
  if (arn[3] !== scope.awsRegion || arn[4] !== scope.awsAccountId) {
    inconsistent.push(GENERAL_ADMISSION_GRANT_PIN_ENV.authorityKeyArn);
  }
  if (pins.storageKeyId === pins.authorityKeyArn) {
    inconsistent.push(GENERAL_ADMISSION_GRANT_PIN_ENV.storageKeyId);
  }
  const prefix = environmentGrantKeyPrefix(scope.environment);
  if (prefix === undefined || !pins.key.startsWith(prefix) || !pins.key.endsWith('.cbor')) {
    inconsistent.push(GENERAL_ADMISSION_GRANT_PIN_ENV.key);
  }
  if (inconsistent.length > 0) {
    throw new GeneralAdmissionGrantPinError(
      'general_admission_grant_pin_inconsistent',
      inconsistent,
    );
  }
}

/** The prefix `resolveGeneralAdmissionPolicyGrantKey` renders both grant key shapes under. */
function environmentGrantKeyPrefix(environment: string): string | undefined {
  try {
    const canonical = generalAdmissionPolicyGrantObjectKey(environment, '0'.repeat(64));
    return `${canonical.split('/grants/')[0]}/`;
  } catch {
    return undefined;
  }
}

/** The published grant a pool's creation is authorized by, or undefined when none is readable. */
export interface PoolCreationGrantSource {
  readPoolCreationGrant(input: {
    poolDeploymentId: string;
  }): Promise<SignedGeneralAdmissionPolicyGrantV1 | undefined>;
}

export interface PoolCreationGrantSourceInput extends GeneralAdmissionGrantScope {
  readonly env: NodeJS.ProcessEnv;
  /** The S3 adapter; the control plane already depends on the client it is built from. */
  readonly objects: GeneralAdmissionPolicyGrantObjectStorePort;
  /** The KMS adapter. */
  readonly authorityKeys: GeneralAdmissionPolicyGrantAuthorityKeyPort;
  readonly trustedTime?: () => Date;
}

/** Composing is synchronous and total: a bad pin fails at startup, not at the first reconcile. */
export function createPoolCreationGrantSource(
  input: PoolCreationGrantSourceInput,
): PoolCreationGrantSource {
  const scope: GeneralAdmissionGrantScope = {
    environment: input.environment,
    awsAccountId: input.awsAccountId,
    awsRegion: input.awsRegion,
  };
  const pins = parseGeneralAdmissionGrantPins({ env: input.env, scope });
  const reader = new GeneralAdmissionPolicyGrantReader(
    input.objects,
    input.authorityKeys,
    { ...pins, ...scope },
    input.trustedTime ?? (() => new Date()),
  );
  return {
    // The pin names exactly one immutable object, so the requested pool selects nothing here: the
    // binding to a pool and generation is `authorizePoolCreation`'s decision, never this read's.
    async readPoolCreationGrant(): Promise<SignedGeneralAdmissionPolicyGrantV1 | undefined> {
      try {
        return await reader.read();
      } catch (error) {
        if (isAbsentGrantObject(error)) return undefined;
        throw error;
      }
    },
  };
}

const ABSENT_OBJECT_NAMES = new Set(['NoSuchKey', 'NoSuchVersion', 'NotFound']);
const ABSENT_OBJECT_STATUS = 404;

/** A pinned object that is gone reads as "no grant", the way an unwritten object does. */
function isAbsentGrantObject(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const name = (error as { name?: unknown }).name;
  if (typeof name === 'string' && name !== 'NoSuchBucket' && ABSENT_OBJECT_NAMES.has(name)) {
    return true;
  }
  const status = (error as { $metadata?: { httpStatusCode?: unknown } }).$metadata?.httpStatusCode;
  return status === ABSENT_OBJECT_STATUS && name !== 'NoSuchBucket';
}
