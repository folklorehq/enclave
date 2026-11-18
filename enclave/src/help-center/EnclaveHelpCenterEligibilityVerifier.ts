// UNWIRED: no composition root builds this yet.
import { GetObjectCommand, type GetObjectCommandOutput, type S3Client } from '@aws-sdk/client-s3';
import {
  designationMacFields,
  visibilityMacFields,
  type HelpCenterDesignationRow,
  type HelpCenterEligibilityVerifierPort,
  type HelpCenterIntegrity,
  type HelpCenterResourceVisibilityRow,
} from '@folklore/api';
import { resourceScopeUnitFor } from '@folklore/contracts';
import { HELP_CENTER_VISIBILITY_MAX_AGE_MS } from '@folklore/contracts/help-center';
import type { Logger } from '@folklore/core';
import {
  isKeyedPlaceRef,
  isLowercaseRfcUuid,
  sha256Hex,
  type KeyedPlaceRef,
} from '@folklore/utils';
import { isFactHelpCenterEligible, type FactEligibility } from '@folklore/wiki';
import { classifyEsdkFailure } from '../crypto/esdk-fault.js';
import { isServiceFault } from '../crypto/service-fault.js';
import type { EnclaveCrypto } from '../crypto/esdk.js';
import type { TenantContext } from '../tenant/tenant-context.js';
import { resolveActivatedTenant } from './activated-tenant.js';
import { attestedFactMacFields } from './attested-fact-fields.js';
import {
  HelpCenterVerifierUnavailableError,
  VERIFIER_UNAVAILABLE_CODE,
} from './HelpCenterVerifierUnavailableError.js';
import type {
  HelpCenterAdapterDeps,
  HelpCenterAttestedFactRow,
  HelpCenterVerifierFact,
  HelpCenterVerifierReadPort,
} from './ports.js';

const REFUSED_EVENT = 'help_center_verifier_refused';
const MAX_SEALED_OBJECT_BYTES = 16 * 1024 * 1024;
const HTTP_FORBIDDEN = 403;
const S3_ABSENT_OBJECT = 'NoSuchKey';
const S3_ACCESS_DENIED = 'AccessDenied';

type Refusal =
  | 'designation_ledger_gap'
  | 'policy_unavailable'
  | 'reads_unavailable'
  | 'storage_unavailable';

interface LiveTenant {
  readonly tenant: TenantContext;
  readonly bucket: string;
}

interface VerificationRun extends LiveTenant {
  readonly orgId: string;
  readonly latest: ReadonlyMap<string, HelpCenterDesignationRow>;
  readonly blocked: ReadonlySet<string>;
  readonly visibility: Map<string, Promise<boolean>>;
}

export interface EnclaveHelpCenterEligibilityVerifierDeps extends HelpCenterAdapterDeps {
  readonly s3: Pick<S3Client, 'send'>;
  readonly integrity: HelpCenterIntegrity;
  readonly reads: HelpCenterVerifierReadPort;
  readonly logger: Logger;
  readonly now?: () => number;
}

// An operational fault throws rather than reads as ineligible, except where AccessDenied is indistinguishable from a missing object.
export class EnclaveHelpCenterEligibilityVerifier implements HelpCenterEligibilityVerifierPort {
  constructor(private readonly deps: EnclaveHelpCenterEligibilityVerifierDeps) {}

  async verifyEligibleFacts(
    orgId: string,
    candidateFactIds: readonly string[],
  ): Promise<ReadonlySet<string>> {
    const live = this.liveTenant(orgId);
    if (live === null) return new Set();
    try {
      return await this.verifyLive(orgId, live, candidateFactIds);
    } catch (error) {
      throw error instanceof HelpCenterVerifierUnavailableError
        ? error
        : this.refuse(orgId, 'storage_unavailable');
    }
  }

  private async verifyLive(
    orgId: string,
    live: LiveTenant,
    candidateFactIds: readonly string[],
  ): Promise<ReadonlySet<string>> {
    const candidates = this.validCandidates(candidateFactIds);
    if (candidates.length === 0) return new Set();
    const latest = await this.latestDesignations(orgId);
    if (latest === null) return this.declineOrg(orgId, 'designation_ledger_gap');
    const blocked = await this.blockedThemes(orgId);
    if (blocked === null) return this.declineOrg(orgId, 'policy_unavailable');
    const facts = await this.readFacts(orgId, candidates);
    const run: VerificationRun = { orgId, ...live, latest, blocked, visibility: new Map() };
    const eligible = new Set<string>();
    for (const candidate of candidates) {
      if (await this.isEligible(run, candidate, facts.get(candidate))) eligible.add(candidate);
    }
    return eligible;
  }

  private liveTenant(orgId: string): LiveTenant | null {
    let resolved: ReturnType<typeof resolveActivatedTenant>;
    try {
      resolved = resolveActivatedTenant(this.deps, orgId, VERIFIER_UNAVAILABLE_CODE);
    } catch {
      throw this.refuse(orgId, 'storage_unavailable');
    }
    if (resolved === null) return null;
    const bucket = resolved.tenant.processedOutputsBucket;
    const probe = resolved.tenant.helpCenterIntegrityKey();
    probe?.fill(0);
    if (probe === null || bucket === '') throw this.refuse(orgId, 'storage_unavailable');
    return { tenant: resolved.tenant, bucket };
  }

  private validCandidates(candidateFactIds: readonly string[]): string[] {
    const unique = new Set(candidateFactIds);
    return [...unique].filter((id) => typeof id === 'string' && isLowercaseRfcUuid(id));
  }

  private async latestDesignations(
    orgId: string,
  ): Promise<ReadonlyMap<string, HelpCenterDesignationRow> | null> {
    const rows = await this.read(orgId, () => this.deps.reads.listDesignations(orgId));
    if (!Array.isArray(rows)) throw this.refuse(orgId, 'reads_unavailable');
    const valid = rows.filter((row) =>
      this.deps.integrity.verify(
        orgId,
        'help_center_source_designations',
        designationMacFields(orgId, row),
        row.mac,
      ),
    );
    if (!this.isContiguous(valid)) return null;
    const latest = new Map<string, HelpCenterDesignationRow>();
    for (const row of valid) {
      const key = this.pairKey(row.sourceKind, row.resourceExternalId);
      if (row.seq > (latest.get(key)?.seq ?? 0)) latest.set(key, row);
    }
    return latest;
  }

  private isContiguous(rows: readonly HelpCenterDesignationRow[]): boolean {
    const seqs = new Set(rows.map((row) => row.seq));
    const max = rows.reduce((highest, row) => Math.max(highest, row.seq), 0);
    const positive = [...seqs].every((seq) => Number.isInteger(seq) && seq >= 1);
    return positive && seqs.size === rows.length && seqs.size === max;
  }

  private async blockedThemes(orgId: string): Promise<ReadonlySet<string> | null> {
    const blocked = await this.read(orgId, () => this.deps.reads.blockedThemeIds(orgId));
    return Array.isArray(blocked) ? new Set(blocked) : null;
  }

  private async readFacts(
    orgId: string,
    candidates: readonly string[],
  ): Promise<ReadonlyMap<string, HelpCenterVerifierFact | null>> {
    const rows = await this.read(orgId, () => this.deps.reads.facts(orgId, candidates));
    if (!Array.isArray(rows)) throw this.refuse(orgId, 'reads_unavailable');
    const wanted = new Set(candidates);
    const byId = new Map<string, HelpCenterVerifierFact | null>();
    for (const row of rows) {
      const id: unknown = row?.factId;
      if (typeof id === 'string' && wanted.has(id)) byId.set(id, byId.has(id) ? null : row);
    }
    return byId;
  }

  private async isEligible(
    run: VerificationRun,
    candidate: string,
    fact: HelpCenterVerifierFact | null | undefined,
  ): Promise<boolean> {
    if (!this.passesFactChecks(run, fact)) return false;
    const signed = fact.attestations.filter((row) => this.isSignedFor(run.orgId, candidate, row));
    const passing: HelpCenterAttestedFactRow[] = [];
    for (const row of signed) if (await this.isDesignated(run, row)) passing.push(row);
    if (passing.length === 0) return false;
    const hash = await this.bodyHash(run, candidate, fact.bodyS3Key);
    const matching = signed.filter((row) => row.bodyHash === hash);
    const [first] = matching;
    return (
      hash !== null &&
      first !== undefined &&
      matching.every((row) => passing.includes(row) && this.samePair(row, first))
    );
  }

  private passesFactChecks(
    run: VerificationRun,
    fact: HelpCenterVerifierFact | null | undefined,
  ): fact is HelpCenterVerifierFact {
    return (
      typeof fact === 'object' &&
      fact !== null &&
      Array.isArray(fact.themeIds) &&
      Array.isArray(fact.attestations) &&
      typeof fact.bodyS3Key === 'string' &&
      fact.bodyS3Key !== '' &&
      fact.deleted === false &&
      fact.superseded === false &&
      !fact.themeIds.some((themeId) => run.blocked.has(themeId))
    );
  }

  private isSignedFor(orgId: string, candidate: string, row: HelpCenterAttestedFactRow): boolean {
    return (
      row?.factId === candidate &&
      isKeyedPlaceRef(row.resourceExternalId) &&
      resourceScopeUnitFor(row.sourceKind) !== undefined &&
      this.deps.integrity.verify(orgId, 'attested_fact', attestedFactMacFields(orgId, row), row.mac)
    );
  }

  private async isDesignated(
    run: VerificationRun,
    row: HelpCenterAttestedFactRow,
  ): Promise<boolean> {
    const latest = run.latest.get(this.pairKey(row.sourceKind, row.resourceExternalId));
    if (latest?.action !== 'designate') return false;
    const eligibility: FactEligibility = {
      sensitivityLevel: row.sensitivityLevel as FactEligibility['sensitivityLevel'],
      designatedSource: true,
      ownerAccountId: row.ownerAccountId,
    };
    if (!isFactHelpCenterEligible(eligibility)) return false;
    return latest.visibilityAtDesignation === false || this.isPublic(run, row);
  }

  private isPublic(run: VerificationRun, row: HelpCenterAttestedFactRow): Promise<boolean> {
    const key = this.pairKey(row.sourceKind, row.resourceExternalId);
    const known = run.visibility.get(key);
    if (known !== undefined) return known;
    const verdict = this.freshlyPublic(run.orgId, row.sourceKind, row.resourceExternalId);
    run.visibility.set(key, verdict);
    return verdict;
  }

  private async freshlyPublic(orgId: string, sourceKind: string, ref: string): Promise<boolean> {
    const rows = await this.read(orgId, () =>
      this.deps.reads.listResourceVisibility(orgId, sourceKind, ref as KeyedPlaceRef),
    );
    if (!Array.isArray(rows)) throw this.refuse(orgId, 'reads_unavailable');
    const newest = this.newestObservation(orgId, rows, sourceKind, ref);
    if (newest === null) return false;
    const age = (this.deps.now ?? Date.now)() - newest.at;
    return newest.row.isPublic === true && age >= 0 && age <= HELP_CENTER_VISIBILITY_MAX_AGE_MS;
  }

  private newestObservation(
    orgId: string,
    rows: readonly HelpCenterResourceVisibilityRow[],
    sourceKind: string,
    ref: string,
  ): { row: HelpCenterResourceVisibilityRow; at: number } | null {
    let newest: { row: HelpCenterResourceVisibilityRow; at: number } | null = null;
    for (const row of rows) {
      const at = Date.parse(row.observedAt);
      const counts =
        row.sourceKind === sourceKind &&
        row.resourceExternalId === ref &&
        Number.isFinite(at) &&
        this.deps.integrity.verify(
          orgId,
          'resource_visibility',
          visibilityMacFields(orgId, row),
          row.mac,
        );
      const supersedes = newest === null || at > newest.at || (at === newest.at && !row.isPublic);
      if (counts && supersedes) newest = { row, at };
    }
    return newest;
  }

  private async bodyHash(
    run: VerificationRun,
    factId: string,
    key: string,
  ): Promise<string | null> {
    const sealed = await this.fetchSealed(run, key);
    const plaintext = sealed === null ? null : await this.open(run, factId, sealed);
    if (plaintext === null) return null;
    try {
      return sha256Hex(plaintext);
    } finally {
      plaintext.fill(0);
    }
  }

  private async fetchSealed(run: VerificationRun, key: string): Promise<Buffer | null> {
    let object: GetObjectCommandOutput;
    try {
      object = await this.deps.s3.send(new GetObjectCommand({ Bucket: run.bucket, Key: key }));
    } catch (error) {
      return this.absentOrUnavailable(run.orgId, error);
    }
    const length = object.ContentLength;
    const sized = typeof length === 'number' && length >= 0 && length <= MAX_SEALED_OBJECT_BYTES;
    if (!sized || object.Body === undefined) {
      this.release(object.Body);
      return null;
    }
    const raw = await object.Body.transformToByteArray();
    if (raw.length > MAX_SEALED_OBJECT_BYTES) return null;
    return Buffer.from(Buffer.from(raw).toString('utf8'), 'base64');
  }

  private release(body: unknown): void {
    const { destroy } = (body ?? {}) as { destroy?: unknown };
    if (typeof destroy === 'function') destroy.call(body);
  }

  private absentOrUnavailable(orgId: string, error: unknown): null {
    const { name, $metadata } = (error ?? {}) as {
      name?: unknown;
      $metadata?: { httpStatusCode?: unknown };
    };
    const status = $metadata?.httpStatusCode;
    const absent =
      name === S3_ABSENT_OBJECT || (status === HTTP_FORBIDDEN && name === S3_ACCESS_DENIED);
    if (isServiceFault(error) || !absent) throw this.refuse(orgId, 'storage_unavailable');
    return null;
  }

  private async open(run: VerificationRun, factId: string, sealed: Buffer): Promise<Buffer | null> {
    try {
      return await this.cryptoOf(run).decryptFactBody(sealed, { factId, orgId: run.orgId });
    } catch (error) {
      if (error instanceof HelpCenterVerifierUnavailableError) throw error;
      this.assertLive(run);
      if (classifyEsdkFailure(error) === 'operational')
        throw this.refuse(run.orgId, 'storage_unavailable');
      return null;
    }
  }

  private assertLive(run: VerificationRun): void {
    this.cryptoOf(run);
  }

  private cryptoOf(run: VerificationRun): EnclaveCrypto {
    try {
      return run.tenant.crypto;
    } catch {
      throw this.refuse(run.orgId, 'storage_unavailable');
    }
  }

  private async read<T>(orgId: string, operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch {
      throw this.refuse(orgId, 'reads_unavailable');
    }
  }

  private samePair(a: HelpCenterAttestedFactRow, b: HelpCenterAttestedFactRow): boolean {
    return a.sourceKind === b.sourceKind && a.resourceExternalId === b.resourceExternalId;
  }

  private pairKey(sourceKind: string, ref: string): string {
    return `${sourceKind}\u0000${ref}`;
  }

  private declineOrg(orgId: string, reason: Refusal): ReadonlySet<string> {
    this.deps.logger.warn(REFUSED_EVENT, { orgId, reason });
    return new Set();
  }

  private refuse(orgId: string, reason: Refusal): HelpCenterVerifierUnavailableError {
    this.deps.logger.warn(REFUSED_EVENT, { orgId, reason });
    return new HelpCenterVerifierUnavailableError();
  }
}
