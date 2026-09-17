import { createHash } from 'node:crypto';
import { verify, type Bundle, type VerifyOptions } from 'sigstore';
import { z } from 'zod';
import {
  assertApprovedBootManifestRoot,
  getBootManifestRootIdentity,
} from './trusted-boot-root-policy.js';
import { TRUSTED_SIGNER_RECOVERY_ROOT_DIGEST } from './trusted-signer-recovery-root.js';

const sourceSha = z.string().regex(/^[0-9a-f]{40}$/);
const RECOVERY_ROOT_SOURCE_ARTIFACT =
  'packages/nitro-attestation/src/trusted-signer-recovery-root.ts';
const TRUSTED_TIME_RECORD_PRODUCER =
  'enclave/src/gate-a/GenerationHighWaterTrustedTimeRecordProducer.ts';
const TRUSTED_TIME_RECORD_VERIFIER = 'enclave/src/gate-a/GenerationHighWaterTrustedTimeVerifier.ts';
const BUILD_IDENTITY_WORKFLOW = 'build-enclave.yml';
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const pcr = z.string().regex(/^(?!0{96}$)[0-9a-f]{96}$/);
const immutableArtifactBucket = z.string().regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]-immutable$/);
const artifactVersionId = z
  .string()
  .min(1)
  .max(1_024)
  .regex(/^[^\s]+$/)
  .refine((value) => value !== 'null');
const bootRootKeyId = z.string().regex(/^[a-z0-9][a-z0-9._-]{2,63}$/);
const EXPECTED_SOURCE_SHA_ENV = 'ENCLAVE_EXPECTED_SOURCE_SHA';

export const attestationManifestSchema = z
  .object({
    schemaVersion: z.literal(1),
    sourceSha,
    builtAt: z.string().datetime({ offset: true }),
    artifact: z
      .object({
        bucket: immutableArtifactBucket,
        key: z.string(),
        versionId: artifactVersionId,
        sha256,
        checksumKey: z.string(),
      })
      .strict(),
    pcrs: z.object({ pcr0: pcr, pcr1: pcr, pcr2: pcr }).strict(),
    provenance: z.object({ key: z.string(), subjectName: z.literal('attestation.json') }).strict(),
    kmsPcrUpdate: z.object({ pcr0: pcr, subjectSha256: sha256 }).strict(),
    tenantBoot: z.object({ artifactKey: z.string(), subjectSha256: sha256 }).strict(),
    bootRoot: z
      .object({
        keyId: bootRootKeyId,
        derSpkiSha256: sha256,
        minimumKeysetGeneration: z.number().int().positive(),
      })
      .strict(),
    recoveryRoot: z
      .object({
        digest: sha256,
        sourceArtifact: z.literal(RECOVERY_ROOT_SOURCE_ARTIFACT),
      })
      .strict(),
    recoveryInstallation: z
      .object({
        state: z.literal('recovery-freeze'),
        acknowledgement: z.literal('pending-all-readers'),
      })
      .strict(),
    trustedTime: z
      .object({
        authority: z.literal('NSM+CLOCK_MONOTONIC_RAW'),
        recordProducer: z.literal(TRUSTED_TIME_RECORD_PRODUCER),
        recordVerifier: z.literal(TRUSTED_TIME_RECORD_VERIFIER),
        hostWallClockAuthority: z.literal(false),
      })
      .strict(),
    buildIdentity: z
      .object({
        sourceSha,
        workflow: z.literal(BUILD_IDENTITY_WORKFLOW),
        buildId: z.string().min(1),
      })
      .strict(),
  })
  .strict()
  .superRefine((manifest, ctx) => {
    const prefix = `artifacts/${manifest.sourceSha}`;
    const artifactKey = `${prefix}/enclave.eif`;
    const bindings = [
      [manifest.artifact.key, artifactKey],
      [manifest.artifact.checksumKey, `${prefix}/enclave.eif.sha256`],
      [manifest.provenance.key, `${prefix}/provenance.json`],
      [manifest.kmsPcrUpdate.pcr0, manifest.pcrs.pcr0],
      [manifest.kmsPcrUpdate.subjectSha256, manifest.artifact.sha256],
      [manifest.tenantBoot.artifactKey, artifactKey],
      [manifest.tenantBoot.subjectSha256, manifest.artifact.sha256],
      [manifest.recoveryRoot.digest, TRUSTED_SIGNER_RECOVERY_ROOT_DIGEST],
      [manifest.buildIdentity.sourceSha, manifest.sourceSha],
      [manifest.buildIdentity.buildId, `enclave-${manifest.sourceSha}`],
    ] as const;
    if (bindings.some(([actual, expected]) => actual !== expected)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'artifact binding mismatch' });
    }
  });

export type AttestationManifestV1 = z.infer<typeof attestationManifestSchema>;

const bundleSchema = z
  .object({
    dsseEnvelope: z.object({ payload: z.string() }).passthrough(),
  })
  .passthrough();

const provenanceStatementSchema = z
  .object({
    _type: z.literal('https://in-toto.io/Statement/v1'),
    subject: z
      .array(z.object({ name: z.string(), digest: z.object({ sha256 }).strict() }).strict())
      .min(1),
    predicateType: z.literal('https://slsa.dev/provenance/v1'),
    predicate: z.unknown(),
  })
  .strict();

const SIGSTORE_ISSUER = 'https://token.actions.githubusercontent.com';
const SIGSTORE_WORKFLOW_OWNER = 'folklorehq';
const SIGSTORE_WORKFLOW_REPOSITORY = 'folklore';
const SIGSTORE_WORKFLOW_FILE = 'build-enclave.yml';
const SIGSTORE_WORKFLOW_IDENTITY = `https://github.com/${SIGSTORE_WORKFLOW_OWNER}/${SIGSTORE_WORKFLOW_REPOSITORY}/.github/workflows/${SIGSTORE_WORKFLOW_FILE}@refs/heads/prod`;
const SIGSTORE_SUBJECT_NAME = 'attestation.json';
const PRODUCTION_WORKFLOW_REF = 'refs/heads/prod';
const PROD_WORKFLOW_IDENTITY = `^${SIGSTORE_WORKFLOW_IDENTITY.replace(
  /[.*+?^${}()|[\]\\]/g,
  '\\$&',
)}$`;

const releaseVerificationSchema = z
  .object({
    sourceSha,
    artifactBucket: immutableArtifactBucket,
    artifactKey: z.string().min(1),
    artifactVersionId,
    artifactSha256: sha256,
    checksumKey: z.string().min(1),
    pcr0: pcr,
    manifestKey: z.string().min(1),
    manifestSha256: sha256,
    provenanceKey: z.string().min(1),
    provenanceSha256: sha256,
    provenanceWorkflowRef: z.literal(PRODUCTION_WORKFLOW_REF),
  })
  .strict();

const releaseProvenanceEnvelopeSchema = z
  .object({
    schemaVersion: z.literal(1),
    releaseVerification: releaseVerificationSchema,
    manifest: z.string().min(1),
    sigstore: z
      .object({
        issuer: z.literal(SIGSTORE_ISSUER),
        workflowIdentity: z.literal(SIGSTORE_WORKFLOW_IDENTITY),
        subjectName: z.literal(SIGSTORE_SUBJECT_NAME),
        subjectSha256: sha256,
        bundle: bundleSchema,
      })
      .strict(),
  })
  .strict();

type ReleaseVerification = z.infer<typeof releaseVerificationSchema>;

import type { VerifiedEnclaveRelease, VerifiedEnclaveReleaseIdentityV1 } from '@folklore/contracts';

export function verifiedEnclaveReleaseIdentity(
  release: VerifiedEnclaveRelease,
): VerifiedEnclaveReleaseIdentityV1 {
  return Object.freeze({
    protectedSourceCommit: release.sourceSha,
    eifArtifactPath: release.enclaveArtifactKey,
    eifDigest: release.enclaveArtifactSha256,
    ...(release.enclaveArtifactVersionId === undefined
      ? {}
      : { eifVersionId: release.enclaveArtifactVersionId }),
    ...(release.manifestVersionId === undefined
      ? {}
      : { manifestVersionId: release.manifestVersionId }),
    ...(release.provenanceVersionId === undefined
      ? {}
      : { provenanceVersionId: release.provenanceVersionId }),
    pcr0: release.pcr0,
  });
}

export interface VerifiedProvenanceSubject {
  subjectName: string;
  subjectSha256: string;
  releaseVerification: ReleaseVerification;
}

export interface EnclaveProvenanceVerifier {
  verify(bundleValue: string, subjectValue: string): Promise<VerifiedProvenanceSubject>;
}

type VerifyBundle = (bundle: Bundle, options: VerifyOptions) => Promise<unknown>;

export class SigstoreEnclaveProvenanceVerifier implements EnclaveProvenanceVerifier {
  constructor(
    private readonly verifyBundle: VerifyBundle = (bundle, options) => verify(bundle, options),
  ) {}

  async verify(bundleValue: string, subjectValue: string): Promise<VerifiedProvenanceSubject> {
    const envelope = releaseProvenanceEnvelopeSchema.parse(JSON.parse(bundleValue) as unknown);
    await this.verifyBundle(envelope.sigstore.bundle as Bundle, {
      certificateIssuer: SIGSTORE_ISSUER,
      certificateIdentityURI: PROD_WORKFLOW_IDENTITY,
    });
    const statement = provenanceStatementSchema.parse(
      JSON.parse(
        Buffer.from(envelope.sigstore.bundle.dsseEnvelope.payload, 'base64').toString('utf8'),
      ) as unknown,
    );
    const subject = statement.subject.find(({ name }) => name === envelope.sigstore.subjectName);
    if (!subject) throw new Error('verified provenance subject is missing');
    const subjectSha256 = createHash('sha256').update(subjectValue, 'utf8').digest('hex');
    if (subject.digest.sha256 !== subjectSha256) {
      throw new Error('verified provenance subject digest does not match attestation.json');
    }
    if (envelope.sigstore.subjectSha256 !== subjectSha256) {
      throw new Error('release provenance subject digest does not match attestation.json');
    }
    if (envelope.releaseVerification.manifestSha256 !== subjectSha256) {
      throw new Error('release provenance manifest digest does not match attestation.json');
    }
    if (envelope.manifest !== subjectValue) {
      throw new Error('release provenance manifest bytes do not match attestation.json');
    }
    if (
      envelope.releaseVerification.provenanceSha256 !==
      createHash('sha256')
        .update(JSON.stringify(canonicalJson(envelope.sigstore.bundle)), 'utf8')
        .digest('hex')
    ) {
      throw new Error('release provenance bundle digest does not match');
    }
    return {
      subjectName: subject.name,
      subjectSha256: subject.digest.sha256,
      releaseVerification: envelope.releaseVerification,
    };
  }
}

// A bounded, log-safe code naming why release evidence was rejected: the silent `undefined` used to be the
// only signal, so a stale env file and a failed deploy looked identical to the consumer that warned.
/** A bounded, log-safe code naming why release evidence was rejected. */
export type VerifiedEnclaveReleaseRejectionReason =
  | 'enclave_release_attestation_manifest_missing'
  | 'enclave_release_provenance_bundle_missing'
  | 'enclave_release_expected_source_sha_invalid'
  | 'enclave_release_manifest_unparseable'
  | 'enclave_release_source_sha_mismatch'
  | 'enclave_release_boot_root_unavailable'
  | 'enclave_release_boot_root_mismatch'
  | 'enclave_release_provenance_verification_failed'
  | 'enclave_release_provenance_subject_mismatch'
  | 'enclave_release_verification_mismatch'
  | 'enclave_release_unexpected_failure';

export interface VerifiedEnclaveReleaseOutcome {
  readonly release: VerifiedEnclaveRelease | undefined;
  /** Absent when release evidence is simply not configured; a bounded code for every rejection. */
  readonly rejectionReason: VerifiedEnclaveReleaseRejectionReason | undefined;
}

function rejectedRelease(
  rejectionReason: VerifiedEnclaveReleaseRejectionReason,
): VerifiedEnclaveReleaseOutcome {
  return { release: undefined, rejectionReason };
}

// The same decision as `parseVerifiedEnclaveRelease`, but it says why instead of only that it refused. No
// severity change: the caller still decides what an unavailable release means.
/** The release decision with the bounded reason for a refusal. */
export async function parseVerifiedEnclaveReleaseOutcome(
  attestationValue: string | undefined,
  provenanceBundleValue: string | undefined,
  verifier: EnclaveProvenanceVerifier,
  expectedSourceSha = process.env[EXPECTED_SOURCE_SHA_ENV],
): Promise<VerifiedEnclaveReleaseOutcome> {
  if (!attestationValue && !provenanceBundleValue) {
    return { release: undefined, rejectionReason: undefined };
  }
  if (!attestationValue) return rejectedRelease('enclave_release_attestation_manifest_missing');
  if (!provenanceBundleValue) return rejectedRelease('enclave_release_provenance_bundle_missing');
  try {
    if (!sourceSha.safeParse(expectedSourceSha).success) {
      return rejectedRelease('enclave_release_expected_source_sha_invalid');
    }
    let manifest: z.infer<typeof attestationManifestSchema>;
    try {
      manifest = attestationManifestSchema.parse(JSON.parse(attestationValue) as unknown);
    } catch {
      return rejectedRelease('enclave_release_manifest_unparseable');
    }
    if (manifest.sourceSha !== expectedSourceSha) {
      return rejectedRelease('enclave_release_source_sha_mismatch');
    }
    try {
      assertApprovedBootManifestRoot();
    } catch {
      return rejectedRelease('enclave_release_boot_root_unavailable');
    }
    const canonicalRoot = getBootManifestRootIdentity();
    if (
      manifest.bootRoot.keyId !== canonicalRoot.keyId ||
      manifest.bootRoot.derSpkiSha256 !== canonicalRoot.derSpkiSha256 ||
      manifest.bootRoot.minimumKeysetGeneration !== canonicalRoot.minimumKeysetGeneration
    ) {
      return rejectedRelease('enclave_release_boot_root_mismatch');
    }
    let verified: VerifiedProvenanceSubject;
    try {
      verified = await verifier.verify(provenanceBundleValue, attestationValue);
    } catch {
      return rejectedRelease('enclave_release_provenance_verification_failed');
    }
    if (verified.subjectName !== manifest.provenance.subjectName) {
      return rejectedRelease('enclave_release_provenance_subject_mismatch');
    }
    if (
      !releaseVerificationMatchesManifest(
        verified.releaseVerification,
        manifest,
        verified.subjectSha256,
      )
    ) {
      return rejectedRelease('enclave_release_verification_mismatch');
    }
    return {
      release: {
        releaseId: verified.releaseVerification.manifestSha256,
        sourceSha: manifest.sourceSha,
        enclaveArtifactBucket: manifest.artifact.bucket,
        enclaveArtifactKey: manifest.artifact.key,
        enclaveArtifactVersionId: manifest.artifact.versionId,
        enclaveArtifactSha256: manifest.artifact.sha256,
        pcr0: manifest.pcrs.pcr0,
      },
      rejectionReason: undefined,
    };
  } catch {
    return rejectedRelease('enclave_release_unexpected_failure');
  }
}

/** The silent contract, unchanged: it keeps only the release and drops the reason. */
export async function parseVerifiedEnclaveRelease(
  attestationValue: string | undefined,
  provenanceBundleValue: string | undefined,
  verifier: EnclaveProvenanceVerifier,
  expectedSourceSha = process.env[EXPECTED_SOURCE_SHA_ENV],
): Promise<VerifiedEnclaveRelease | undefined> {
  const outcome = await parseVerifiedEnclaveReleaseOutcome(
    attestationValue,
    provenanceBundleValue,
    verifier,
    expectedSourceSha,
  );
  return outcome.release;
}
export function releaseVerificationMatchesManifest(
  release: ReleaseVerification,
  manifest: z.infer<typeof attestationManifestSchema>,
  manifestSha256: string,
): boolean {
  const sourcePrefix = `artifacts/${manifest.sourceSha}`;
  return (
    release.sourceSha === manifest.sourceSha &&
    release.artifactBucket === manifest.artifact.bucket &&
    release.artifactKey === manifest.artifact.key &&
    release.artifactVersionId === manifest.artifact.versionId &&
    release.artifactSha256 === manifest.artifact.sha256 &&
    release.checksumKey === manifest.artifact.checksumKey &&
    release.pcr0 === manifest.pcrs.pcr0 &&
    release.manifestKey === `${sourcePrefix}/attestation.json` &&
    release.manifestSha256 === manifestSha256 &&
    release.provenanceKey === manifest.provenance.key &&
    release.provenanceWorkflowRef === PRODUCTION_WORKFLOW_REF
  );
}

function canonicalJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value as Record<string, unknown>)
      .sort()
      .map((key) => [key, canonicalJson((value as Record<string, unknown>)[key])]),
  );
}
