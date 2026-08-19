import {
  enclaveRuntimeEvidenceSchema,
  poolRuntimeAttestationUserDataSchema,
  type BootManifestUserData,
  type EnclaveRuntimeEvidence,
  type PoolRuntimeAttestationUserData,
  type RuntimeDatabaseCredentialReceipt,
} from '@folklore/contracts/enclave-attestation';
import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify,
  type KeyObject,
  X509Certificate,
} from 'node:crypto';

import {
  encodeAttestationUserData,
  encodePoolRuntimeAttestationUserData,
  encodePoolRuntimeHealthSignaturePayload,
  encodeRuntimeHealthSignaturePayload,
  hashNitroDocument,
  hashRuntimeAttestationKeyBundle,
} from './canonical-cbor.js';
import { NitroAttestationError, type NitroAttestationFailureCode } from './failures.js';
import { parseNitroCoseSign1 } from './nitro-cose-sign1.js';
import { verifyNitroCoseSignature } from './nitro-cose-signature.js';
import {
  parseNitroDocumentPayload,
  parseNitroDocumentTrustPathPayload,
  type NitroDocumentPayload,
} from './nitro-document-payload.js';
import { verifyCertificatePath } from './x509-path.js';
import { loadAwsNitroRoot } from './aws-nitro-root.js';
import { derivePcr3FromRoleArn, derivePcr4FromInstanceId } from './nitro-pcr.js';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const CLOCK_SKEW_MS = 5_000;
const CHALLENGE_NONCE_BYTES = 32;
const PCR_BYTES = 48;

export interface RuntimeAttestationExpectations {
  nonce: Uint8Array;
  userData: BootManifestUserData;
  pcr0: Uint8Array;
  parentRoleArn: string;
  instanceId: string;
  challengeIssuedAt: Date;
  challengeExpiresAt: Date;
  serverTime: Date;
  runtimeKeyBundleHash?: string;
}

export interface VerifiedRuntimeIdentity {
  documentTimestamp: number;
  documentHash: string;
  pcr0: string;
  pcr3: string;
  pcr4: string;
  bootManifestHash: string;
  configurationGeneration: number;
  orgId: string;
  deploymentId: string;
  sourceSha: string;
  eifDigest: string;
  kmsKeyArn: string;
  parentRoleArn: string;
  instanceId: string;
  sessionPublicKeySha256: string;
  healthObservedAt: string;
  runtimeKeyBundleHash?: string;
  responseEncryptionPublicKey?: string;
  ingestPublicKey?: string;
}

export type RuntimeAttestationResult =
  | { ok: true; identity: VerifiedRuntimeIdentity }
  | { ok: false; failure: NitroAttestationFailureCode };

export interface PoolRuntimeAttestationExpectations {
  nonce: Uint8Array;
  poolDeploymentId: string;
  assignmentGeneration: number;
  assignmentDigest: string;
  pcr0: Uint8Array;
  parentRoleArn: string;
  instanceId: string;
  challengeIssuedAt: Date;
  challengeExpiresAt: Date;
  serverTime: Date;
}

export interface VerifiedPoolRuntimeIdentity {
  documentTimestamp: number;
  documentHash: string;
  pcr0: string;
  pcr3: string;
  pcr4: string;
  poolDeploymentId: string;
  assignmentGeneration: number;
  assignmentDigest: string;
  runtimeDatabase: RuntimeDatabaseCredentialReceipt;
  parentRoleArn: string;
  instanceId: string;
  sessionPublicKeySha256: string;
  healthObservedAt: string;
}

export type PoolRuntimeAttestationResult =
  | { ok: true; identity: VerifiedPoolRuntimeIdentity }
  | { ok: false; failure: NitroAttestationFailureCode };

export type AwsNitroAttestationDocumentResult =
  | { ok: true }
  | { ok: false; failure: NitroAttestationFailureCode };

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

function validateExpectations(expected: RuntimeAttestationExpectations): void {
  const issuedAt = expected.challengeIssuedAt.getTime();
  const expiresAt = expected.challengeExpiresAt.getTime();
  const serverTime = expected.serverTime.getTime();
  const datesAreValid = [issuedAt, expiresAt, serverTime].every(Number.isFinite);
  const pcr0IsValid =
    expected.pcr0.byteLength === PCR_BYTES && expected.pcr0.some((byte) => byte !== 0);
  if (
    !datesAreValid ||
    issuedAt >= expiresAt ||
    expected.nonce.byteLength !== CHALLENGE_NONCE_BYTES ||
    !pcr0IsValid ||
    !/^arn:[a-z0-9-]+:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]+$/.test(expected.parentRoleArn) ||
    !/^i-[0-9a-f]{8,17}$/.test(expected.instanceId)
  ) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
}

function validatePoolExpectations(expected: PoolRuntimeAttestationExpectations): void {
  const issuedAt = expected.challengeIssuedAt.getTime();
  const expiresAt = expected.challengeExpiresAt.getTime();
  const serverTime = expected.serverTime.getTime();
  const pcr0IsValid =
    expected.pcr0.byteLength === PCR_BYTES && expected.pcr0.some((byte) => byte !== 0);
  if (
    ![issuedAt, expiresAt, serverTime].every(Number.isFinite) ||
    issuedAt >= expiresAt ||
    expected.nonce.byteLength !== CHALLENGE_NONCE_BYTES ||
    !pcr0IsValid ||
    !/^arn:[a-z0-9-]+:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]+$/.test(expected.parentRoleArn) ||
    !/^i-[0-9a-f]{8,17}$/.test(expected.instanceId) ||
    !/^[0-9a-f]{64}$/.test(expected.assignmentDigest)
  ) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
}

function ed25519PublicKey(raw: Uint8Array): KeyObject {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function verifyDocumentBindings(
  payload: NitroDocumentPayload,
  evidence: EnclaveRuntimeEvidence,
  expected: RuntimeAttestationExpectations,
): void {
  const evidencePublicKey = Buffer.from(evidence.sessionPublicKey, 'base64');
  const bundle = evidence.runtimeKeyBundle;
  if (!bundle) throw new NitroAttestationError('runtime_binding_mismatch');
  const bundleHash = hashRuntimeAttestationKeyBundle(bundle);
  const expectedUserData = encodeAttestationUserData(expected.userData, bundleHash);
  const expectedPcrs = [
    [0, expected.pcr0],
    [3, derivePcr3FromRoleArn(expected.parentRoleArn)],
    [4, derivePcr4FromInstanceId(expected.instanceId)],
  ] as const;
  if (
    !bytesEqual(payload.nonce, expected.nonce) ||
    !bytesEqual(payload.userData, expectedUserData)
  ) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
  if (!bytesEqual(payload.publicKey, evidencePublicKey)) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
  if (bundle.signingPublicKey !== evidence.sessionPublicKey) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
  const bundleKeys = [
    bundle.signingPublicKey,
    bundle.responseEncryptionPublicKey,
    bundle.ingestPublicKey,
  ].map((value) => Buffer.from(value, 'base64'));
  if (bundleKeys.some((key) => key.byteLength !== 32)) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
  if (expected.runtimeKeyBundleHash !== undefined && expected.runtimeKeyBundleHash !== bundleHash) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
  for (const [index, expectedPcr] of expectedPcrs) {
    const actualPcr = payload.pcrs.get(index);
    if (actualPcr === undefined || !bytesEqual(actualPcr, expectedPcr)) {
      throw new NitroAttestationError('runtime_binding_mismatch');
    }
  }
}

function verifyTimes(
  payload: NitroDocumentPayload,
  expected: Pick<
    RuntimeAttestationExpectations,
    'challengeIssuedAt' | 'challengeExpiresAt' | 'serverTime'
  >,
): void {
  const lower = expected.challengeIssuedAt.getTime() - CLOCK_SKEW_MS;
  const upper =
    Math.min(expected.challengeExpiresAt.getTime(), expected.serverTime.getTime()) + CLOCK_SKEW_MS;
  if (payload.timestamp < lower || payload.timestamp > upper) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
}

function verifyHealth(
  document: Uint8Array,
  payload: NitroDocumentPayload,
  evidence: EnclaveRuntimeEvidence,
  expected: RuntimeAttestationExpectations,
): void {
  const { record } = evidence.signedHealth;
  const observedAt = Date.parse(record.observedAt);
  const lower = expected.challengeIssuedAt.getTime();
  const upper = expected.challengeExpiresAt.getTime();
  if (
    observedAt < lower ||
    observedAt > upper ||
    observedAt > expected.serverTime.getTime() + CLOCK_SKEW_MS
  ) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
  if (
    record.status !== 'healthy' ||
    !record.tenantAssigned ||
    !record.bootManifestVerified ||
    !record.kmsUnsealed ||
    !record.tenantApiReady
  ) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
  const signed = encodeRuntimeHealthSignaturePayload({
    nonce: expected.nonce,
    documentHash: hashNitroDocument(document),
    manifestHash: expected.userData.manifestHash,
    configurationGeneration: expected.userData.configurationGeneration,
    record,
  });
  if (
    !verify(
      null,
      signed,
      ed25519PublicKey(payload.publicKey),
      Buffer.from(evidence.signedHealth.signature, 'base64'),
    )
  ) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
}

function normalizedIdentity(
  document: Uint8Array,
  payload: NitroDocumentPayload,
  expected: RuntimeAttestationExpectations,
  evidence: EnclaveRuntimeEvidence,
): VerifiedRuntimeIdentity {
  return {
    documentTimestamp: payload.timestamp,
    documentHash: hashNitroDocument(document),
    pcr0: Buffer.from(payload.pcrs.get(0) ?? []).toString('hex'),
    pcr3: Buffer.from(payload.pcrs.get(3) ?? []).toString('hex'),
    pcr4: Buffer.from(payload.pcrs.get(4) ?? []).toString('hex'),
    bootManifestHash: expected.userData.manifestHash,
    configurationGeneration: expected.userData.configurationGeneration,
    orgId: expected.userData.orgId,
    deploymentId: expected.userData.deploymentId,
    sourceSha: expected.userData.sourceSha,
    eifDigest: expected.userData.eifDigest,
    kmsKeyArn: expected.userData.kmsKeyArn,
    parentRoleArn: expected.parentRoleArn,
    instanceId: expected.instanceId,
    sessionPublicKeySha256: createHash('sha256').update(payload.publicKey).digest('hex'),
    healthObservedAt: evidence.signedHealth.record.observedAt,
    ...(evidence.runtimeKeyBundle
      ? {
          runtimeKeyBundleHash: hashRuntimeAttestationKeyBundle(evidence.runtimeKeyBundle),
          responseEncryptionPublicKey: evidence.runtimeKeyBundle.responseEncryptionPublicKey,
          ingestPublicKey: evidence.runtimeKeyBundle.ingestPublicKey,
        }
      : {}),
  };
}

function poolUserData(
  evidence: EnclaveRuntimeEvidence,
  expected: PoolRuntimeAttestationExpectations,
): PoolRuntimeAttestationUserData {
  const runtimeDatabase = evidence.signedHealth.record.runtimeDatabase;
  if (!runtimeDatabase) throw new NitroAttestationError('runtime_binding_mismatch');
  const sessionPublicKey = Buffer.from(evidence.sessionPublicKey, 'base64');
  if (sessionPublicKey.byteLength !== 32) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
  return poolRuntimeAttestationUserDataSchema.parse({
    version: 1,
    poolDeploymentId: expected.poolDeploymentId,
    assignmentGeneration: expected.assignmentGeneration,
    assignmentDigest: expected.assignmentDigest,
    runtimeDatabase,
    sessionPublicKeySha256: createHash('sha256').update(sessionPublicKey).digest('hex'),
  });
}

function verifyPoolDocumentBindings(
  payload: NitroDocumentPayload,
  evidence: EnclaveRuntimeEvidence,
  expected: PoolRuntimeAttestationExpectations,
  userData: PoolRuntimeAttestationUserData,
): void {
  const evidencePublicKey = Buffer.from(evidence.sessionPublicKey, 'base64');
  const expectedPcrs = [
    [0, expected.pcr0],
    [3, derivePcr3FromRoleArn(expected.parentRoleArn)],
    [4, derivePcr4FromInstanceId(expected.instanceId)],
  ] as const;
  if (
    !bytesEqual(payload.nonce, expected.nonce) ||
    !bytesEqual(payload.userData, encodePoolRuntimeAttestationUserData(userData)) ||
    !bytesEqual(payload.publicKey, evidencePublicKey)
  ) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
  for (const [index, expectedPcr] of expectedPcrs) {
    const actualPcr = payload.pcrs.get(index);
    if (actualPcr === undefined || !bytesEqual(actualPcr, expectedPcr)) {
      throw new NitroAttestationError('runtime_binding_mismatch');
    }
  }
}

function verifyPoolHealth(
  document: Uint8Array,
  payload: NitroDocumentPayload,
  evidence: EnclaveRuntimeEvidence,
  expected: PoolRuntimeAttestationExpectations,
  userData: PoolRuntimeAttestationUserData,
): void {
  const { record } = evidence.signedHealth;
  const observedAt = Date.parse(record.observedAt);
  if (
    observedAt < expected.challengeIssuedAt.getTime() ||
    observedAt > expected.challengeExpiresAt.getTime() ||
    observedAt > expected.serverTime.getTime() + CLOCK_SKEW_MS ||
    record.status !== 'healthy' ||
    !record.tenantAssigned ||
    record.bootManifestVerified ||
    record.runtimeTrust !== 'pool-assignment' ||
    record.assignmentManifestVerified !== true ||
    !record.kmsUnsealed ||
    !record.tenantApiReady ||
    !record.runtimeDatabase
  ) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
  const signed = encodePoolRuntimeHealthSignaturePayload({
    nonce: expected.nonce,
    documentHash: hashNitroDocument(document),
    userData,
    record,
  });
  if (
    !verify(
      null,
      signed,
      ed25519PublicKey(payload.publicKey),
      Buffer.from(evidence.signedHealth.signature, 'base64'),
    )
  ) {
    throw new NitroAttestationError('runtime_binding_mismatch');
  }
}

function normalizedPoolIdentity(
  document: Uint8Array,
  payload: NitroDocumentPayload,
  expected: PoolRuntimeAttestationExpectations,
  evidence: EnclaveRuntimeEvidence,
  userData: PoolRuntimeAttestationUserData,
): VerifiedPoolRuntimeIdentity {
  return {
    documentTimestamp: payload.timestamp,
    documentHash: hashNitroDocument(document),
    pcr0: Buffer.from(payload.pcrs.get(0) ?? []).toString('hex'),
    pcr3: Buffer.from(payload.pcrs.get(3) ?? []).toString('hex'),
    pcr4: Buffer.from(payload.pcrs.get(4) ?? []).toString('hex'),
    poolDeploymentId: userData.poolDeploymentId,
    assignmentGeneration: userData.assignmentGeneration,
    assignmentDigest: userData.assignmentDigest,
    runtimeDatabase: userData.runtimeDatabase,
    parentRoleArn: expected.parentRoleArn,
    instanceId: expected.instanceId,
    sessionPublicKeySha256: userData.sessionPublicKeySha256,
    healthObservedAt: evidence.signedHealth.record.observedAt,
  };
}

export function verifyAwsNitroAttestationDocument(
  document: Uint8Array,
  verificationTime?: Date,
): AwsNitroAttestationDocumentResult {
  try {
    const cose = parseNitroCoseSign1(document);
    const payload = parseNitroDocumentTrustPathPayload(cose.payload);
    const leafKey = verifyCertificatePath({
      leafDer: payload.certificate,
      cabundle: payload.cabundle,
      trustedRootDer: new X509Certificate(loadAwsNitroRoot()).raw,
      verificationTime: verificationTime ?? new Date(payload.timestamp),
    });
    verifyNitroCoseSignature(cose, leafKey);
    return { ok: true };
  } catch (error: unknown) {
    return {
      ok: false,
      failure: error instanceof NitroAttestationError ? error.code : 'malformed_document',
    };
  }
}

export function verifyRuntimeAttestationWithTrustAnchor(
  rawEvidence: EnclaveRuntimeEvidence,
  expected: RuntimeAttestationExpectations,
  trustedRootDer: Uint8Array,
): RuntimeAttestationResult {
  try {
    validateExpectations(expected);
    const evidence = enclaveRuntimeEvidenceSchema.parse(rawEvidence);
    const document = Buffer.from(evidence.nitroDocument, 'base64');
    const cose = parseNitroCoseSign1(document);
    const payload = parseNitroDocumentPayload(cose.payload);
    const leafKey = verifyCertificatePath({
      leafDer: payload.certificate,
      cabundle: payload.cabundle,
      trustedRootDer,
      verificationTime: expected.serverTime,
    });
    verifyNitroCoseSignature(cose, leafKey);
    verifyDocumentBindings(payload, evidence, expected);
    verifyTimes(payload, expected);
    verifyHealth(document, payload, evidence, expected);
    return { ok: true, identity: normalizedIdentity(document, payload, expected, evidence) };
  } catch (error: unknown) {
    return {
      ok: false,
      failure: error instanceof NitroAttestationError ? error.code : 'malformed_document',
    };
  }
}

export function verifyRuntimeAttestation(
  evidence: EnclaveRuntimeEvidence,
  expected: RuntimeAttestationExpectations,
): RuntimeAttestationResult {
  const trustedRootDer = new X509Certificate(loadAwsNitroRoot()).raw;
  return verifyRuntimeAttestationWithTrustAnchor(evidence, expected, trustedRootDer);
}

export function verifyPoolRuntimeAttestationWithTrustAnchor(
  rawEvidence: EnclaveRuntimeEvidence,
  expected: PoolRuntimeAttestationExpectations,
  trustedRootDer: Uint8Array,
): PoolRuntimeAttestationResult {
  try {
    validatePoolExpectations(expected);
    const evidence = enclaveRuntimeEvidenceSchema.parse(rawEvidence);
    const userData = poolUserData(evidence, expected);
    const document = Buffer.from(evidence.nitroDocument, 'base64');
    const cose = parseNitroCoseSign1(document);
    const payload = parseNitroDocumentPayload(cose.payload);
    const leafKey = verifyCertificatePath({
      leafDer: payload.certificate,
      cabundle: payload.cabundle,
      trustedRootDer,
      verificationTime: expected.serverTime,
    });
    verifyNitroCoseSignature(cose, leafKey);
    verifyPoolDocumentBindings(payload, evidence, expected, userData);
    verifyTimes(payload, expected);
    verifyPoolHealth(document, payload, evidence, expected, userData);
    return {
      ok: true,
      identity: normalizedPoolIdentity(document, payload, expected, evidence, userData),
    };
  } catch (error: unknown) {
    return {
      ok: false,
      failure: error instanceof NitroAttestationError ? error.code : 'malformed_document',
    };
  }
}

export function verifyPoolRuntimeAttestation(
  evidence: EnclaveRuntimeEvidence,
  expected: PoolRuntimeAttestationExpectations,
): PoolRuntimeAttestationResult {
  const trustedRootDer = new X509Certificate(loadAwsNitroRoot()).raw;
  return verifyPoolRuntimeAttestationWithTrustAnchor(evidence, expected, trustedRootDer);
}
