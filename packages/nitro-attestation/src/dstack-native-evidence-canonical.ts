import { createHash } from 'node:crypto';
import { aciDstackRawEvidenceV1Schema, type AciDstackRawEvidenceV1 } from '@folklore/contracts';
import { canonicalCbor } from './canonical-cbor.js';
import { domainSeparatedBytes, sha256Hex } from './model-provenance-canonical.js';

export const DSTACK_NATIVE_EVIDENCE_V1_DOMAIN = 'folklore.dstack-native-evidence.v1';
export const DSTACK_RAW_EVIDENCE_V2_DOMAIN = 'folklore.dstack-raw-evidence.v2';

const STRICT_BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export interface DstackNativeEvidenceUpstreamAppInfoV1 {
  readonly appIdDigest: string;
  readonly composeHashDigest: string;
  readonly instanceIdDigest: string;
  readonly deviceIdDigest: string;
  readonly mrSystemDigest: string;
  readonly mrAggregatedDigest: string;
  readonly osImageHashDigest: string;
  readonly keyProviderInfoDigest: string;
}

export interface DstackNativeEvidenceUpstreamV1 {
  readonly quoteVerified: boolean;
  readonly eventLogVerified: boolean;
  readonly osImageHashVerified: boolean;
  readonly acpiTablesVerified: boolean;
  readonly teeVariant: string;
  readonly reportData: string;
  readonly tcbStatus: string;
  readonly advisoryIds: readonly string[];
  readonly appInfo: DstackNativeEvidenceUpstreamAppInfoV1;
}

export interface DstackNativeEvidenceV1 {
  readonly sessionId: string;
  readonly workloadKeysetDigest: string;
  readonly quoteBase64: string;
  readonly collateralBase64: string;
  readonly eventLog: string;
  readonly vmConfig: string;
  readonly rtmr: string;
  readonly runtimeIdentityDigest: string;
  readonly workloadArtifactDigest: string;
  readonly routeIdentityDigest: string;
  readonly tcbStatus: string;
  readonly kmsRootDigests: readonly string[];
  readonly channelPinDigests: readonly string[];
  readonly upstream: DstackNativeEvidenceUpstreamV1;
}

export interface DstackNativeEvidenceDigestResultV1 {
  readonly nativeEvidenceDigest: string;
  readonly quoteDigest: string;
  readonly collateralDigest: string;
  readonly eventLogDigest: string;
  readonly vmConfigDigest: string;
}

export interface DstackRawEvidenceDigestV2 {
  readonly evidenceDigest: string;
  readonly quoteDigest: string;
  readonly collateralDigest: string;
  readonly eventLogDigest: string;
  readonly vmConfigDigest: string;
}

export function digestDstackRawEvidenceV2(
  evidence: AciDstackRawEvidenceV1,
): DstackRawEvidenceDigestV2 {
  evidence = aciDstackRawEvidenceV1Schema.parse(evidence);
  const quoteDigest = sha256Hex(Buffer.from(evidence.quote_base64, 'base64'));
  const collateralDigest = sha256Hex(Buffer.from(evidence.collateral_base64, 'base64'));
  const eventLogDigest = sha256Hex(Buffer.from(evidence.event_log_base64, 'base64'));
  const vmConfigDigest = sha256Hex(Buffer.from(evidence.vm_config_base64, 'base64'));
  const evidenceDigest = sha256Hex(
    domainSeparatedBytes(DSTACK_RAW_EVIDENCE_V2_DOMAIN, [
      evidence.version,
      evidence.format,
      evidence.session_id,
      evidence.workload_keyset_digest,
      quoteDigest,
      collateralDigest,
      eventLogDigest,
      vmConfigDigest,
    ]),
  );
  return { evidenceDigest, quoteDigest, collateralDigest, eventLogDigest, vmConfigDigest };
}

export class DstackRawEvidenceDigestAuthority {
  digest(evidence: AciDstackRawEvidenceV1): string {
    return `sha256:${digestDstackRawEvidenceV2(evidence).evidenceDigest}`;
  }
}

function assertStrictBase64(value: string, label: string): void {
  if (!STRICT_BASE64_PATTERN.test(value)) throw new TypeError(`invalid ${label}`);
}

function assertSortedUnique(values: readonly string[], label: string): void {
  for (let index = 0; index < values.length; index += 1) {
    const previous = values[index - 1];
    const current = values[index];
    if (current === undefined) throw new TypeError(`invalid ${label}`);
    if (previous !== undefined && previous >= current) throw new TypeError(`invalid ${label}`);
  }
}

function validateDstackNativeEvidence(input: DstackNativeEvidenceV1): void {
  assertStrictBase64(input.quoteBase64, 'quote');
  assertStrictBase64(input.collateralBase64, 'collateral');
  assertSortedUnique(input.kmsRootDigests, 'kmsRootDigests');
  assertSortedUnique(input.channelPinDigests, 'channelPinDigests');
  assertSortedUnique(input.upstream.advisoryIds, 'advisoryIds');
}

function dstackComponentDigests(
  input: DstackNativeEvidenceV1,
): Omit<DstackNativeEvidenceDigestResultV1, 'nativeEvidenceDigest'> {
  return {
    quoteDigest: createHash('sha256')
      .update(Buffer.from(input.quoteBase64, 'base64'))
      .digest('hex'),
    collateralDigest: createHash('sha256')
      .update(Buffer.from(input.collateralBase64, 'base64'))
      .digest('hex'),
    eventLogDigest: createHash('sha256').update(Buffer.from(input.eventLog, 'utf8')).digest('hex'),
    vmConfigDigest: createHash('sha256').update(Buffer.from(input.vmConfig, 'utf8')).digest('hex'),
  };
}

function dstackNativeEvidenceFields(input: DstackNativeEvidenceV1): unknown[] {
  validateDstackNativeEvidence(input);
  const digests = dstackComponentDigests(input);
  return [
    DSTACK_NATIVE_EVIDENCE_V1_DOMAIN,
    input.sessionId,
    input.workloadKeysetDigest,
    digests.quoteDigest,
    digests.collateralDigest,
    digests.eventLogDigest,
    digests.vmConfigDigest,
    input.rtmr,
    input.runtimeIdentityDigest,
    input.workloadArtifactDigest,
    input.routeIdentityDigest,
    input.tcbStatus,
    [...input.kmsRootDigests],
    [...input.channelPinDigests],
    [
      input.upstream.quoteVerified,
      input.upstream.eventLogVerified,
      input.upstream.osImageHashVerified,
      input.upstream.acpiTablesVerified,
      input.upstream.teeVariant,
      input.upstream.reportData,
      input.upstream.tcbStatus,
      [...input.upstream.advisoryIds],
      [
        input.upstream.appInfo.appIdDigest,
        input.upstream.appInfo.composeHashDigest,
        input.upstream.appInfo.instanceIdDigest,
        input.upstream.appInfo.deviceIdDigest,
        input.upstream.appInfo.mrSystemDigest,
        input.upstream.appInfo.mrAggregatedDigest,
        input.upstream.appInfo.osImageHashDigest,
        input.upstream.appInfo.keyProviderInfoDigest,
      ],
    ],
  ];
}

export function canonicalDstackNativeEvidenceArrayV1(input: DstackNativeEvidenceV1): Uint8Array {
  return canonicalCbor(dstackNativeEvidenceFields(input));
}

export function encodeDstackNativeEvidenceV1(input: DstackNativeEvidenceV1): Uint8Array {
  return domainSeparatedBytes(DSTACK_NATIVE_EVIDENCE_V1_DOMAIN, dstackNativeEvidenceFields(input));
}

// The helper returns the native evidence identity and all four component digests from one
// implementation so Dstack binding code consumes a single shared value.
export function digestDstackNativeEvidenceV1(
  input: DstackNativeEvidenceV1,
): DstackNativeEvidenceDigestResultV1 {
  const components = dstackComponentDigests(input);
  return {
    ...components,
    nativeEvidenceDigest: sha256Hex(encodeDstackNativeEvidenceV1(input)),
  };
}
