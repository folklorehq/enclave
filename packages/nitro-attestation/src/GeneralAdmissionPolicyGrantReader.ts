import { createHash, createPublicKey, verify as verifyEd25519 } from 'node:crypto';
import {
  signedGeneralAdmissionPolicyGrantV1Schema,
  type SignedGeneralAdmissionPolicyGrantV1,
} from '@folklore/contracts';
import {
  computeGeneralAdmissionPolicyGrantDigestV1,
  generalAdmissionPolicyGrantSignatureInputV1,
} from './tenant-policy-admission.js';
import { canonicalCbor } from './canonical-cbor.js';
import * as cborg from 'cborg';

const MAX_GRANT_BYTES = 64 * 1024;

/** The observed facts of the pinned object; a field the store did not return is undefined. */
export interface GeneralAdmissionPolicyGrantObject {
  readonly versionId: string | undefined;
  readonly objectLockMode: string | undefined;
  readonly objectLockLegalHoldStatus: string | undefined;
  readonly sseKmsKeyId: string | undefined;
  readonly objectLockRetainUntilDate: Date | undefined;
  readonly body: unknown;
}

/** Reads the pinned object; a failure propagates unchanged so the reader decides what it means. */
export interface GeneralAdmissionPolicyGrantObjectStorePort {
  readObject(input: {
    readonly bucket: string;
    readonly key: string;
    readonly versionId: string;
    readonly signal?: AbortSignal;
  }): Promise<GeneralAdmissionPolicyGrantObject>;
}

/** The observed facts of the pinned signing key; a field KMS did not describe is undefined. */
export interface GeneralAdmissionPolicyGrantAuthorityKeyDescription {
  readonly arn: string | undefined;
  readonly keyId: string | undefined;
  readonly keyState: string | undefined;
  readonly keySpec: string | undefined;
  readonly keyUsage: string | undefined;
  readonly multiRegion: boolean | undefined;
  readonly keyManager: string | undefined;
  readonly origin: string | undefined;
  readonly signingAlgorithms: readonly string[] | undefined;
}

/** Describes and publishes the pinned authority key. Failures propagate as they arrived. */
export interface GeneralAdmissionPolicyGrantAuthorityKeyPort {
  describeKey(input: {
    readonly keyArn: string;
    readonly signal?: AbortSignal;
  }): Promise<GeneralAdmissionPolicyGrantAuthorityKeyDescription>;
  getPublicKey(input: {
    readonly keyArn: string;
    readonly signal?: AbortSignal;
  }): Promise<{ readonly publicKeyDer: Uint8Array | undefined }>;
}

export interface GeneralAdmissionPolicyGrantReaderConfig {
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly objectDigest: string;
  readonly storageKeyId: string;
  readonly authorityKeyArn: string;
  readonly authorityKeyId: string;
  readonly authorityPublicKeySpkiSha256: string;
  readonly authorityEpoch: number;
  readonly environment: string;
  readonly awsAccountId: string;
  readonly awsRegion: string;
}

export class GeneralAdmissionPolicyGrantReader {
  constructor(
    private readonly objects: GeneralAdmissionPolicyGrantObjectStorePort,
    private readonly authorityKeys: GeneralAdmissionPolicyGrantAuthorityKeyPort,
    private readonly config: GeneralAdmissionPolicyGrantReaderConfig,
    private readonly trustedTime: () => Date,
  ) {}

  async read(
    input: { readonly signal?: AbortSignal } = {},
  ): Promise<SignedGeneralAdmissionPolicyGrantV1> {
    input.signal?.throwIfAborted();
    const response = await this.objects.readObject({
      bucket: this.config.bucket,
      key: this.config.key,
      versionId: this.config.versionId,
      signal: input.signal,
    });
    input.signal?.throwIfAborted();
    if (response.versionId !== this.config.versionId)
      throw new Error('general_admission_grant_version_mismatch');
    if (response.objectLockMode !== 'COMPLIANCE')
      throw new Error('general_admission_grant_retention_mismatch');
    if (response.objectLockLegalHoldStatus !== 'ON')
      throw new Error('general_admission_grant_legal_hold_missing');
    if (response.sseKmsKeyId !== this.config.storageKeyId)
      throw new Error('general_admission_grant_storage_key_mismatch');
    const bytes = await readBody(response.body);
    if (sha256Hex(bytes) !== this.config.objectDigest)
      throw new Error('general_admission_grant_object_digest_mismatch');
    const signed = signedGeneralAdmissionPolicyGrantV1Schema.parse(cborg.decode(bytes));
    if (!bytesEqual(canonicalCbor(signed), bytes))
      throw new Error('general_admission_grant_canonical_mismatch');
    const grant = signed.grant;
    if (grant.grantDigest !== computeGeneralAdmissionPolicyGrantDigestV1(grant.subject))
      throw new Error('general_admission_grant_digest_mismatch');
    await this.verifyAuthority(grant, input.signal);
    if (
      grant.subject.environment !== this.config.environment ||
      grant.subject.awsAccountId !== this.config.awsAccountId ||
      grant.subject.awsRegion !== this.config.awsRegion
    )
      throw new Error('general_admission_grant_scope_mismatch');
    const now = this.trustedTime().getTime();
    const expiresAt = Date.parse(grant.subject.expiresAt);
    if (now < Date.parse(grant.subject.issuedAt) || now >= expiresAt)
      throw new Error('general_admission_grant_stale');
    const retainUntil = response.objectLockRetainUntilDate?.getTime();
    if (retainUntil === undefined || !Number.isFinite(retainUntil) || retainUntil < expiresAt)
      throw new Error('general_admission_grant_retention_mismatch');
    input.signal?.throwIfAborted();
    const publicKeyDer = await this.readAuthorityPublicKey(input.signal);
    const publicKey = createPublicKey({
      key: Buffer.from(publicKeyDer),
      format: 'der',
      type: 'spki',
    });
    if (
      !verifyEd25519(
        null,
        generalAdmissionPolicyGrantSignatureInputV1(grant),
        publicKey,
        Buffer.from(signed.signature, 'base64'),
      )
    )
      throw new Error('general_admission_grant_signature_invalid');
    return signed;
  }

  private async verifyAuthority(
    grant: SignedGeneralAdmissionPolicyGrantV1['grant'],
    signal?: AbortSignal,
  ): Promise<void> {
    signal?.throwIfAborted();
    if (
      grant.authority.keyArn !== this.config.authorityKeyArn ||
      grant.authority.keyId !== this.config.authorityKeyId ||
      grant.authority.publicKeySpkiSha256 !== this.config.authorityPublicKeySpkiSha256 ||
      grant.authority.epoch !== this.config.authorityEpoch
    )
      throw new Error('general_admission_grant_authority_mismatch');
    const metadata = await this.authorityKeys.describeKey({
      keyArn: this.config.authorityKeyArn,
      signal,
    });
    if (
      metadata.arn !== this.config.authorityKeyArn ||
      metadata.keyId !== this.config.authorityKeyId ||
      metadata.keyState !== 'Enabled' ||
      metadata.keySpec !== 'ECC_NIST_EDWARDS25519' ||
      metadata.keyUsage !== 'SIGN_VERIFY' ||
      metadata.multiRegion === true ||
      metadata.keyManager !== 'CUSTOMER' ||
      metadata.origin !== 'AWS_KMS'
    )
      throw new Error('general_admission_grant_authority_kms_mismatch');
    const algorithms = metadata.signingAlgorithms ?? [];
    // AWS KMS lists both ED25519_PH_SHA_512 and ED25519_SHA_512 for Ed25519 keys; require the
    // signing algorithm we use to be present rather than the only entry.
    if (!algorithms.includes('ED25519_SHA_512'))
      throw new Error('general_admission_grant_authority_kms_mismatch');
  }

  private async readAuthorityPublicKey(signal?: AbortSignal): Promise<Uint8Array> {
    signal?.throwIfAborted();
    const response = await this.authorityKeys.getPublicKey({
      keyArn: this.config.authorityKeyArn,
      signal,
    });
    const publicKeyDer = response.publicKeyDer;
    if (publicKeyDer === undefined) throw new Error('general_admission_grant_spki_mismatch');
    const bytes = Uint8Array.from(publicKeyDer);
    if (sha256Hex(bytes) !== this.config.authorityPublicKeySpkiSha256)
      throw new Error('general_admission_grant_spki_mismatch');
    return bytes;
  }
}

async function readBody(body: unknown): Promise<Uint8Array> {
  if (body instanceof Uint8Array) {
    if (body.byteLength > MAX_GRANT_BYTES)
      throw new Error('general_admission_grant_body_too_large');
    return Uint8Array.from(body);
  }
  if (
    body !== null &&
    typeof body === 'object' &&
    'transformToByteArray' in body &&
    typeof body.transformToByteArray === 'function'
  ) {
    const value = await body.transformToByteArray();
    if (value.byteLength > MAX_GRANT_BYTES)
      throw new Error('general_admission_grant_body_too_large');
    return Uint8Array.from(value);
  }
  throw new Error('general_admission_grant_body_invalid');
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength && left.every((value, index) => value === right[index])
  );
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}
