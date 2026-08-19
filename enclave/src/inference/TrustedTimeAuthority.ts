import { createHash, randomBytes } from 'node:crypto';

import {
  trustedTimeBindingV1Schema,
  trustedTimeSampleV1Schema,
  type TrustedTimeBindingV1,
  type TrustedTimeSampleV1,
} from '@folklore/contracts';
import type {
  MonotonicRawClockPort,
  NsmAttestationDocumentV1,
  NsmTrustedTimeSourcePort,
  TrustedTimeAuthorityV1Port,
  TrustedTimeDecisionReason,
  TrustedTimeReadContext,
  TrustedTimeSample,
} from '@folklore/inference';

interface TrustedTimeCheckpoint {
  readonly binding: TrustedTimeBindingV1;
  readonly nsmTimestampMs: number;
  readonly rawBeforeNs: bigint;
  readonly rawAfterNs: bigint;
  readonly checkpointDigest: string;
}

interface AttestedSample {
  readonly document: NsmAttestationDocumentV1;
  readonly rawBeforeNs: bigint;
  readonly rawAfterNs: bigint;
}

export interface TrustedTimeAuthorityOptions {
  readonly nsm: NsmTrustedTimeSourcePort;
  readonly clock: MonotonicRawClockPort;
  readonly nonceGenerator?: () => Uint8Array;
  readonly sampleWindowBoundMs?: number;
  readonly maximumCheckpointAgeMs?: number;
  readonly maximumResampleDriftMs?: number;
}

export type TrustedTimeAuthorityErrorCode =
  | 'trusted_time_config_invalid'
  | 'trusted_time_context_mismatch'
  | 'trusted_time_uninitialized'
  | 'trusted_time_reason_invalid'
  | 'nsm_attestation_invalid'
  | 'clock_raw_read_failed'
  | 'clock_raw_rollback'
  | 'trusted_time_expired'
  | 'trusted_time_drift';

const NONCE_BYTES = 32;
const MAX_USER_DATA_BYTES = 512;
const NANOSECONDS_PER_MILLISECOND = 1_000_000n;
const DEFAULT_SAMPLE_WINDOW_BOUND_MS = 1_000;
const DEFAULT_MAXIMUM_CHECKPOINT_AGE_MS = 60_000;
const DEFAULT_MAXIMUM_RESAMPLE_DRIFT_MS = 2_000;
const MAX_SAMPLE_WINDOW_BOUND_MS = 1_000;
const MAX_CHECKPOINT_AGE_MS = 60_000;
const MAX_RESAMPLE_DRIFT_MS = 2_000;
const DIGEST = /^[0-9a-f]{64}$/;
const MEASUREMENT = /^[0-9a-f]{96}$/;
const DECISION_REASONS = new Set<TrustedTimeDecisionReason>([
  'proof',
  'lease',
  'first-byte',
  'receipt',
  'expiry',
  'rollback',
  'release',
]);

export class TrustedTimeAuthorityError extends Error {
  constructor(public readonly code: TrustedTimeAuthorityErrorCode) {
    super(code);
    this.name = 'TrustedTimeAuthorityError';
  }
}

export class TrustedTimeAuthority implements TrustedTimeAuthorityV1Port {
  #binding: TrustedTimeBindingV1 | undefined;
  #checkpoint: TrustedTimeCheckpoint | undefined;
  #lastRawNs: bigint | undefined;
  #healthy = false;
  readonly #usedNonces = new Set<string>();

  private readonly nonceGenerator: () => Uint8Array;
  private readonly sampleWindowBoundMs: number;
  private readonly maximumCheckpointAgeMs: number;
  private readonly maximumResampleDriftMs: number;

  constructor(private readonly options: TrustedTimeAuthorityOptions) {
    this.nonceGenerator = options.nonceGenerator ?? (() => randomBytes(NONCE_BYTES));
    this.sampleWindowBoundMs = options.sampleWindowBoundMs ?? DEFAULT_SAMPLE_WINDOW_BOUND_MS;
    this.maximumCheckpointAgeMs =
      options.maximumCheckpointAgeMs ?? DEFAULT_MAXIMUM_CHECKPOINT_AGE_MS;
    this.maximumResampleDriftMs =
      options.maximumResampleDriftMs ?? DEFAULT_MAXIMUM_RESAMPLE_DRIFT_MS;
    this.validateOptions();
  }

  async initialize(binding: TrustedTimeBindingV1): Promise<void> {
    this.close();
    try {
      const parsedBinding = this.validateBinding(binding);
      const checkpoint = await this.createCheckpoint(parsedBinding);
      this.#binding = parsedBinding;
      this.#checkpoint = checkpoint;
      this.#healthy = true;
    } catch (error: unknown) {
      this.close();
      if (error instanceof TrustedTimeAuthorityError) throw error;
      throw this.failure('nsm_attestation_invalid');
    }
  }

  async sample(reason: TrustedTimeDecisionReason): Promise<TrustedTimeSampleV1> {
    if (!DECISION_REASONS.has(reason)) throw this.failure('trusted_time_reason_invalid');
    const binding = this.#binding;
    const checkpoint = this.#checkpoint;
    if (!this.#healthy || binding === undefined || checkpoint === undefined) {
      throw this.failure('trusted_time_uninitialized');
    }

    try {
      const rawBeforeSampleNs = this.readRawClock();
      this.assertCheckpointAge(checkpoint, rawBeforeSampleNs);
      const attested = await this.attest(binding);
      this.assertCheckpointAge(checkpoint, attested.rawAfterNs);
      this.assertFreshTimestamp(checkpoint, attested.rawAfterNs, attested.document.timestampMs);
      const bounds = this.boundsAt(checkpoint, attested.rawAfterNs);
      const sample = {
        orgId: binding.orgId,
        deploymentId: binding.deploymentId,
        bootEpoch: binding.bootEpoch,
        trustedNowMs: bounds.lowerMs,
        latestPossibleNowMs: bounds.upperMs,
        checkpointDigest: checkpoint.checkpointDigest,
        health: 'healthy' as const,
      };
      const parsed = trustedTimeSampleV1Schema.safeParse(sample);
      if (!parsed.success) throw this.closeWithFailure('trusted_time_expired');
      return parsed.data;
    } catch (error: unknown) {
      this.close();
      if (error instanceof TrustedTimeAuthorityError) throw error;
      throw this.failure('nsm_attestation_invalid');
    }
  }

  isHealthy(): boolean {
    return this.#healthy;
  }

  async read(context: TrustedTimeReadContext = {}): Promise<TrustedTimeSample> {
    const sample = await this.sample('proof');
    if (
      (context.orgId !== undefined && context.orgId !== sample.orgId) ||
      (context.deploymentId !== undefined && context.deploymentId !== sample.deploymentId) ||
      (context.bootEpoch !== undefined && context.bootEpoch !== sample.bootEpoch) ||
      (context.checkpointDigest !== undefined &&
        context.checkpointDigest !== sample.checkpointDigest)
    ) {
      throw this.failure('trusted_time_context_mismatch');
    }
    return {
      trustedNow: sample.trustedNowMs,
      checkpointDigest: sample.checkpointDigest,
      bootEpoch: sample.bootEpoch,
      orgId: sample.orgId,
      deploymentId: sample.deploymentId,
    };
  }

  private async createCheckpoint(binding: TrustedTimeBindingV1): Promise<TrustedTimeCheckpoint> {
    const attested = await this.attest(binding);
    return {
      binding,
      nsmTimestampMs: attested.document.timestampMs,
      rawBeforeNs: attested.rawBeforeNs,
      rawAfterNs: attested.rawAfterNs,
      checkpointDigest: this.checkpointDigest(binding, attested.document),
    };
  }

  private async attest(binding: TrustedTimeBindingV1): Promise<AttestedSample> {
    const rawBeforeNs = this.readRawClock();
    const nonce = this.freshNonce();
    const userData = this.bindingUserData(binding);
    let document: NsmAttestationDocumentV1;
    try {
      document = await this.options.nsm.attest({
        nonce: Uint8Array.from(nonce),
        userData: Uint8Array.from(userData),
      });
    } catch {
      throw this.failure('nsm_attestation_invalid');
    }
    const rawAfterNs = this.readRawClock();
    if (rawAfterNs < rawBeforeNs) throw this.closeWithFailure('clock_raw_rollback');
    if (rawAfterNs - rawBeforeNs > BigInt(this.sampleWindowBoundMs) * NANOSECONDS_PER_MILLISECOND) {
      throw this.failure('nsm_attestation_invalid');
    }
    this.validateAttestation(document, binding, nonce, userData);
    return { document, rawBeforeNs, rawAfterNs };
  }

  private validateOptions(): void {
    if (
      !this.isBoundedPositiveInteger(this.sampleWindowBoundMs, MAX_SAMPLE_WINDOW_BOUND_MS) ||
      !this.isBoundedPositiveInteger(this.maximumCheckpointAgeMs, MAX_CHECKPOINT_AGE_MS) ||
      !Number.isSafeInteger(this.maximumResampleDriftMs) ||
      this.maximumResampleDriftMs < 0 ||
      this.maximumResampleDriftMs > MAX_RESAMPLE_DRIFT_MS
    ) {
      throw this.failure('trusted_time_config_invalid');
    }
  }

  private validateBinding(binding: TrustedTimeBindingV1): TrustedTimeBindingV1 {
    const parsed = trustedTimeBindingV1Schema.safeParse(binding);
    if (!parsed.success) throw this.failure('trusted_time_config_invalid');
    return parsed.data;
  }

  private validateAttestation(
    document: NsmAttestationDocumentV1,
    binding: TrustedTimeBindingV1,
    nonce: Uint8Array,
    userData: Uint8Array,
  ): void {
    if (
      document === null ||
      typeof document !== 'object' ||
      document.chainVerified !== true ||
      document.rootVerified !== true ||
      document.signatureVerified !== true ||
      !Number.isSafeInteger(document.timestampMs) ||
      document.timestampMs <= 0 ||
      !this.equalBytes(document.nonce, nonce) ||
      !this.equalBytes(document.userData, userData) ||
      document.pcr0 !== binding.pcr0 ||
      !MEASUREMENT.test(document.pcr0) ||
      !DIGEST.test(document.documentDigest) ||
      (document.publicKey !== null &&
        (!(document.publicKey instanceof Uint8Array) || document.publicKey.byteLength !== 32))
    ) {
      throw this.failure('nsm_attestation_invalid');
    }
  }

  private freshNonce(): Uint8Array {
    let nonce: Uint8Array;
    try {
      nonce = this.nonceGenerator();
    } catch {
      throw this.failure('nsm_attestation_invalid');
    }
    if (!(nonce instanceof Uint8Array) || nonce.byteLength !== NONCE_BYTES) {
      throw this.failure('nsm_attestation_invalid');
    }
    const copy = Uint8Array.from(nonce);
    const key = Buffer.from(copy).toString('hex');
    if (this.#usedNonces.has(key)) throw this.failure('nsm_attestation_invalid');
    this.#usedNonces.add(key);
    return copy;
  }

  private bindingUserData(binding: TrustedTimeBindingV1): Uint8Array {
    const encoded = JSON.stringify(this.bindingValues(binding));
    const userData = new TextEncoder().encode(encoded);
    if (userData.byteLength === 0 || userData.byteLength > MAX_USER_DATA_BYTES) {
      throw this.failure('nsm_attestation_invalid');
    }
    return userData;
  }

  private bindingValues(binding: TrustedTimeBindingV1): readonly unknown[] {
    return [
      'folklore.trusted-time.v1',
      binding.orgId,
      binding.deploymentId,
      binding.bootEpoch,
      binding.releaseId,
      binding.eifDigest,
      binding.pcr0,
      binding.bootRootDigest,
      binding.policyGeneration,
      binding.activationGeneration,
      binding.keysetEpoch,
      binding.keysetDigest,
    ];
  }

  private checkpointDigest(
    binding: TrustedTimeBindingV1,
    document: NsmAttestationDocumentV1,
  ): string {
    return createHash('sha256')
      .update(
        JSON.stringify([
          'folklore.trusted-time-checkpoint.v1',
          ...this.bindingValues(binding),
          document.timestampMs,
          document.documentDigest,
        ]),
      )
      .digest('hex');
  }

  private assertCheckpointAge(checkpoint: TrustedTimeCheckpoint, rawNowNs: bigint): void {
    if (
      rawNowNs - checkpoint.rawBeforeNs >
      BigInt(this.maximumCheckpointAgeMs) * NANOSECONDS_PER_MILLISECOND
    ) {
      throw this.closeWithFailure('trusted_time_expired');
    }
  }

  private assertFreshTimestamp(
    checkpoint: TrustedTimeCheckpoint,
    rawNowNs: bigint,
    timestampMs: number,
  ): void {
    const bounds = this.boundsAt(checkpoint, rawNowNs);
    if (
      timestampMs < bounds.lowerMs - this.maximumResampleDriftMs ||
      timestampMs > bounds.upperMs + this.maximumResampleDriftMs
    ) {
      throw this.closeWithFailure('trusted_time_drift');
    }
  }

  private boundsAt(
    checkpoint: TrustedTimeCheckpoint,
    rawNowNs: bigint,
  ): { lowerMs: number; upperMs: number } {
    const lowerElapsedMs = this.elapsedMilliseconds(rawNowNs - checkpoint.rawAfterNs, false);
    const upperElapsedMs = this.elapsedMilliseconds(rawNowNs - checkpoint.rawBeforeNs, true);
    const lowerMs = checkpoint.nsmTimestampMs + lowerElapsedMs;
    const upperMs = checkpoint.nsmTimestampMs + upperElapsedMs;
    if (
      !Number.isSafeInteger(lowerMs) ||
      !Number.isSafeInteger(upperMs) ||
      lowerMs <= 0 ||
      upperMs < lowerMs
    ) {
      throw this.closeWithFailure('trusted_time_expired');
    }
    return { lowerMs, upperMs };
  }

  private readRawClock(): bigint {
    let value: bigint;
    try {
      value = this.options.clock.readNanoseconds();
    } catch {
      throw this.closeWithFailure('clock_raw_read_failed');
    }
    if (typeof value !== 'bigint' || value < 0n) {
      throw this.closeWithFailure('clock_raw_read_failed');
    }
    if (this.#lastRawNs !== undefined && value < this.#lastRawNs) {
      throw this.closeWithFailure('clock_raw_rollback');
    }
    this.#lastRawNs = value;
    return value;
  }

  private elapsedMilliseconds(elapsedNs: bigint, roundUp: boolean): number {
    if (elapsedNs < 0n) throw this.closeWithFailure('clock_raw_rollback');
    const quotient = elapsedNs / NANOSECONDS_PER_MILLISECOND;
    const hasRemainder = elapsedNs % NANOSECONDS_PER_MILLISECOND !== 0n;
    const milliseconds = roundUp && hasRemainder ? quotient + 1n : quotient;
    if (milliseconds > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw this.closeWithFailure('trusted_time_expired');
    }
    return Number(milliseconds);
  }

  private isBoundedPositiveInteger(value: number, maximum: number): boolean {
    return Number.isSafeInteger(value) && value > 0 && value <= maximum;
  }

  private equalBytes(left: Uint8Array, right: Uint8Array): boolean {
    return (
      left instanceof Uint8Array &&
      left.byteLength === right.byteLength &&
      left.every((value, index) => value === right[index])
    );
  }

  private closeWithFailure(code: TrustedTimeAuthorityErrorCode): TrustedTimeAuthorityError {
    this.close();
    return this.failure(code);
  }

  private close(): void {
    this.#healthy = false;
    this.#binding = undefined;
    this.#checkpoint = undefined;
    this.#lastRawNs = undefined;
  }

  private failure(code: TrustedTimeAuthorityErrorCode): TrustedTimeAuthorityError {
    return new TrustedTimeAuthorityError(code);
  }
}
