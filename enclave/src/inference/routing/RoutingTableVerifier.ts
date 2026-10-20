import {
  ROUTABLE_INFERENCE_PROVIDERS,
  ROUTING_TABLE_MAX_BYTES,
  routingTableBodyRefusal,
  signedInferenceRoutingTableV1Schema,
  type InferenceProviderId,
  type InferenceRoutingTableV1,
  type RoutingTableRefusal,
} from '@folklore/contracts';
import {
  INFERENCE_ROUTING_TABLE_V1_DOMAIN,
  digestInferenceRoutingTableV1,
  inferenceRoutingTableSignatureInputV1,
} from '@folklore/nitro-attestation';
import type { ActivePolicyCarrierKeyVerifierPort } from '@folklore/inference';
import type { RoutingParameterValue } from './AwsRoutingParameterReader.js';

const POLICY_AUTHORITY_PURPOSE = 'policy-authority';

export interface RoutingTableTrust {
  readonly keyVerifier: ActivePolicyCarrierKeyVerifierPort;
  readonly authorityKeyId: string;
  readonly awsAccountId: string;
  readonly awsRegion: string;
  readonly expectedParameterArn: string;
}

export interface VerifiedRoutingTable {
  readonly table: InferenceRoutingTableV1;
  readonly digest: string;
}

export class RoutingTableRefusalError extends Error {
  constructor(readonly code: RoutingTableRefusal) {
    super(code);
    this.name = 'RoutingTableRefusalError';
  }
}

export class RoutingTableVerifier {
  private readonly routableProviders: ReadonlySet<InferenceProviderId>;

  constructor(
    private readonly trust: RoutingTableTrust,
    enabledProviders: ReadonlySet<InferenceProviderId>,
    private readonly allowedAnthropicModels: ReadonlySet<string>,
    private readonly now: () => number = Date.now,
  ) {
    this.routableProviders = new Set(
      [...enabledProviders].filter((provider) => ROUTABLE_INFERENCE_PROVIDERS.includes(provider)),
    );
  }

  async verify(
    read: RoutingParameterValue,
    highWaterVersion: number,
  ): Promise<VerifiedRoutingTable> {
    if (read.arn !== this.trust.expectedParameterArn) {
      RoutingTableVerifier.refuse('routing_table_scope_mismatch');
    }
    const value = read.value ?? '';
    if (Buffer.byteLength(value, 'utf8') > ROUTING_TABLE_MAX_BYTES)
      RoutingTableVerifier.refuse('routing_table_oversize');
    const signed = this.parse(value);
    if (signed.signerKeyId !== this.trust.authorityKeyId)
      RoutingTableVerifier.refuse('routing_table_signer_mismatch');
    await this.assertSignature(signed.table, signed.signerKeyId, signed.signature);
    this.assertScope(signed.table);
    this.assertBody(signed.table, highWaterVersion);
    this.assertIdentityModels(signed.table);
    return { table: signed.table, digest: digestInferenceRoutingTableV1(signed.table) };
  }

  private parse(value: string) {
    let json: unknown;
    try {
      json = JSON.parse(value);
    } catch {
      return RoutingTableVerifier.refuse('routing_table_schema_invalid');
    }
    const parsed = signedInferenceRoutingTableV1Schema.safeParse(json);
    return parsed.success
      ? parsed.data
      : RoutingTableVerifier.refuse('routing_table_schema_invalid');
  }

  private async assertSignature(
    table: InferenceRoutingTableV1,
    keyId: string,
    signature: string,
  ): Promise<void> {
    try {
      await this.trust.keyVerifier.assertSignaturePurpose({
        purpose: POLICY_AUTHORITY_PURPOSE,
        keyId,
        domain: INFERENCE_ROUTING_TABLE_V1_DOMAIN,
        canonicalBytes: inferenceRoutingTableSignatureInputV1(table),
        signature,
      });
    } catch {
      RoutingTableVerifier.refuse('routing_table_signature_invalid');
    }
  }

  private assertScope(table: InferenceRoutingTableV1): void {
    if (
      table.awsAccountId !== this.trust.awsAccountId ||
      table.awsRegion !== this.trust.awsRegion
    ) {
      RoutingTableVerifier.refuse('routing_table_scope_mismatch');
    }
  }

  private assertIdentityModels(table: InferenceRoutingTableV1): void {
    const routes = [table.purposes, ...table.orgOverrides.map(({ purposes }) => purposes)].flatMap(
      (purposes) => Object.values(purposes),
    );
    const targets = routes.flatMap((route) => [route, ...route.fallbacks]);
    if (
      targets.some(
        (target) =>
          target.provider === 'anthropic' && !this.allowedAnthropicModels.has(target.model),
      )
    ) {
      RoutingTableVerifier.refuse('routing_table_model_not_routable');
    }
  }

  private assertBody(table: InferenceRoutingTableV1, highWaterVersion: number): void {
    const { schema: _schema, awsAccountId: _account, awsRegion: _region, ...body } = table;
    const refusal = routingTableBodyRefusal(body, {
      nowMs: this.now(),
      highWaterVersion,
      routableProviders: this.routableProviders,
    });
    if (refusal !== undefined) RoutingTableVerifier.refuse(refusal);
  }

  private static refuse(code: RoutingTableRefusal): never {
    throw new RoutingTableRefusalError(code);
  }
}
