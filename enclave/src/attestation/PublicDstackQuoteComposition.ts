import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AciPublicQuoteVerifierPort } from '@folklore/inference';
import { DstackPublicNativeVerifier } from './DstackPublicNativeVerifier.js';

export const PUBLIC_DSTACK_EXECUTABLE = '/usr/local/bin/folklore-dstack-verifier';
export const PUBLIC_DSTACK_COLLATERAL_PATH =
  '/usr/local/share/folklore/attestation/phala-tdx-collateral.json';
export const PUBLIC_DSTACK_COLLATERAL_SHA256 =
  '689c1a531486f41bc14a45844ed273174360b6a5ceaa5a6d8a398c577d1aba3e';
const PRODUCTION_QUOTE_ROOT = '44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3';
const MAX_COLLATERAL_BYTES = 1_048_576;

/** Offline collateral is data, not a verdict. Native verification checks its validity every call. */
export function createPublicDstackQuoteVerifier(): AciPublicQuoteVerifierPort {
  const collateral = readFileSync(PUBLIC_DSTACK_COLLATERAL_PATH);
  if (
    collateral.byteLength === 0 ||
    collateral.byteLength > MAX_COLLATERAL_BYTES ||
    createHash('sha256').update(collateral).digest('hex') !== PUBLIC_DSTACK_COLLATERAL_SHA256
  ) {
    throw new Error('public_dstack_collateral_invalid');
  }
  const collateralBase64 = collateral.toString('base64');
  return {
    async verify({ evidence, evaluationTimeUnixSeconds, signal }) {
      if (
        signal.aborted ||
        !Number.isSafeInteger(evaluationTimeUnixSeconds) ||
        evaluationTimeUnixSeconds <= 0
      )
        return undefined;
      // The report core supplies this value only after reading its trusted-time authority.
      // Keep the same sample throughout this bounded operation, not a wall-clock fallback.
      const native = new DstackPublicNativeVerifier({
        executablePath: PUBLIC_DSTACK_EXECUTABLE,
        nowUnixSeconds: () => evaluationTimeUnixSeconds,
        quoteRootDigestHex: PRODUCTION_QUOTE_ROOT,
        expectedTcbStatus: 'UpToDate',
      });
      const result = await native.verify({
        quoteBase64: Buffer.from(evidence.quote, 'hex').toString('base64'),
        collateralBase64,
        eventLog: evidence.event_log,
        vmConfig: evidence.vm_config,
        evaluationTimeUnixSeconds,
      });
      return signal.aborted ? undefined : result;
    },
  };
}
