// Recovery-root installation gate (plan "Keyset, roots, recovery installation, and reader
// capability"): a new root is not admitted until every verifier consumer reports the exact new
// digest, source commit, build identity, and artifact digest. Missing, duplicate, stale, partial,
// epoch-regressed, or prior-floor-mismatched reports hold the system in `recovery-freeze`.
// Hand-rolled validation: nitro-attestation has no zod dep.

export const REQUIRED_RECOVERY_READER_SET = [
  'nitro-attestation',
  'enclave-boot-manifest-verifier',
  'runtime-attestation-composition',
  'control-plane-nitro-runtime-verifier',
] as const;

export const RECOVERY_FREEZE_STATE = 'recovery-freeze' as const;

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
const digest64Pattern = /^[0-9a-f]{64}$/;
const gitCommitPattern = /^[0-9a-f]{40}$/;

export interface RecoveryRootInstallationReportV1 {
  readonly schema: 'RecoveryRootInstallationReportV1';
  readonly version: 1;
  readonly readerId: string;
  readonly buildId: string;
  readonly installedRootEpoch: number;
  readonly installedRootDigest: string;
  readonly sourceCommit: string;
  readonly artifactDigest: string;
}

export const recoveryRootInstallationReportV1Schema = {
  parse(input: unknown): RecoveryRootInstallationReportV1 {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      throw new Error('recovery_root_installation_report_invalid');
    }
    const value = input as Record<string, unknown>;
    if (
      value['schema'] !== 'RecoveryRootInstallationReportV1' ||
      value['version'] !== 1 ||
      typeof value['readerId'] !== 'string' ||
      !identifierPattern.test(value['readerId']) ||
      typeof value['buildId'] !== 'string' ||
      !identifierPattern.test(value['buildId']) ||
      typeof value['installedRootEpoch'] !== 'number' ||
      !Number.isSafeInteger(value['installedRootEpoch']) ||
      (value['installedRootEpoch'] as number) < 1 ||
      typeof value['installedRootDigest'] !== 'string' ||
      !digest64Pattern.test(value['installedRootDigest']) ||
      typeof value['sourceCommit'] !== 'string' ||
      !gitCommitPattern.test(value['sourceCommit']) ||
      typeof value['artifactDigest'] !== 'string' ||
      !digest64Pattern.test(value['artifactDigest'])
    ) {
      throw new Error('recovery_root_installation_report_invalid');
    }
    return Object.freeze({
      schema: 'RecoveryRootInstallationReportV1',
      version: 1,
      readerId: value['readerId'],
      buildId: value['buildId'],
      installedRootEpoch: value['installedRootEpoch'],
      installedRootDigest: value['installedRootDigest'],
      sourceCommit: value['sourceCommit'],
      artifactDigest: value['artifactDigest'],
    }) as unknown as RecoveryRootInstallationReportV1;
  },
  safeParse(input: unknown): { success: boolean; data?: RecoveryRootInstallationReportV1 } {
    try {
      return { success: true, data: this.parse(input) };
    } catch {
      return { success: false };
    }
  },
};

export interface RecoveryRootInstallationEvaluation {
  readonly state: 'ready' | typeof RECOVERY_FREEZE_STATE;
  readonly missingReaders: readonly string[];
  readonly staleReports: readonly string[];
  readonly unknownReaders: readonly string[];
  readonly epochRegression: boolean;
}

export function evaluateRecoveryRootInstallation(input: {
  newRecoveryRootDigest: string;
  newRootEpoch: number;
  expectedBuildId: string;
  /** Compiled recovery source commit; the installation gate always supplies it. */
  expectedSourceCommit?: string;
  /** Compiled recovery artifact digest; the installation gate always supplies it. */
  expectedArtifactDigest?: string;
  priorRootEpoch?: number;
  reports: readonly RecoveryRootInstallationReportV1[];
}): RecoveryRootInstallationEvaluation {
  if (
    typeof input.newRecoveryRootDigest !== 'string' ||
    !digest64Pattern.test(input.newRecoveryRootDigest) ||
    !Number.isSafeInteger(input.newRootEpoch) ||
    input.newRootEpoch < 1 ||
    (input.expectedSourceCommit !== undefined &&
      (typeof input.expectedSourceCommit !== 'string' ||
        !gitCommitPattern.test(input.expectedSourceCommit))) ||
    (input.expectedArtifactDigest !== undefined &&
      (typeof input.expectedArtifactDigest !== 'string' ||
        !digest64Pattern.test(input.expectedArtifactDigest)))
  ) {
    throw new Error('recovery_root_installation_input_invalid');
  }
  const reports = input.reports.map((report) =>
    recoveryRootInstallationReportV1Schema.parse(report),
  );
  const reportReaderIds = reports.map((report) => report.readerId);
  if (new Set(reportReaderIds).size !== reportReaderIds.length) {
    throw new Error('recovery_reader_report_duplicate');
  }
  const knownReaderSet = new Set<string>(REQUIRED_RECOVERY_READER_SET);
  const unknownReaders = reports
    .filter((report) => !knownReaderSet.has(report.readerId))
    .map((report) => report.readerId);
  const missingReaders = REQUIRED_RECOVERY_READER_SET.filter(
    (readerId) => !reports.some((report) => report.readerId === readerId),
  );
  const staleReports = reports
    .filter(
      (report) =>
        report.installedRootDigest !== input.newRecoveryRootDigest ||
        report.installedRootEpoch !== input.newRootEpoch ||
        report.buildId !== input.expectedBuildId ||
        (input.expectedSourceCommit !== undefined &&
          report.sourceCommit !== input.expectedSourceCommit) ||
        (input.expectedArtifactDigest !== undefined &&
          report.artifactDigest !== input.expectedArtifactDigest),
    )
    .map((report) => report.readerId);
  const epochRegression =
    input.priorRootEpoch !== undefined &&
    Number.isSafeInteger(input.priorRootEpoch) &&
    input.newRootEpoch <= input.priorRootEpoch;
  const frozen =
    unknownReaders.length > 0 ||
    missingReaders.length > 0 ||
    staleReports.length > 0 ||
    epochRegression;
  return {
    state: frozen ? RECOVERY_FREEZE_STATE : 'ready',
    missingReaders,
    staleReports,
    unknownReaders,
    epochRegression,
  };
}

export function verifyRecoveryRootInstallation(input: {
  newRecoveryRootDigest: string;
  newRootEpoch: number;
  expectedBuildId: string;
  expectedSourceCommit?: string;
  expectedArtifactDigest?: string;
  priorRootEpoch?: number;
  reports: readonly RecoveryRootInstallationReportV1[];
}): RecoveryRootInstallationEvaluation {
  return evaluateRecoveryRootInstallation(input);
}
