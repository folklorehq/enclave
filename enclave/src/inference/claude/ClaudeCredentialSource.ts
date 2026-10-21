import { sha256Hex } from '@folklore/utils';
import type { ClaudeModelId } from '@folklore/contracts';
import type {
  AttestedParameterRead,
  AttestedParameterReadErrors,
  AttestedSsmParameterReader,
} from '../../attestation/AttestedSsmParameterReader.js';
import type { VerifiedBootManifest } from '../../attestation/BootManifestVerifier.js';
import {
  ANTHROPIC_MODELS_PATH_PREFIX,
  ANTHROPIC_ORIGIN,
  type AnthropicTransport,
} from '../../egress/anthropic-transport.js';
import {
  UPSTREAM_TIMEOUT_CAUSE,
  transportFailureOf,
} from '../../egress/anthropic-transport-failure.js';
import {
  AttestedProviderKeyReader,
  type ProviderKeyManifest,
} from '../credentials/AttestedProviderKeyReader.js';
import { ProviderKeyHolder, type KeyInvalidation } from '../credentials/ProviderKeyHolder.js';
import { ClaudeRouteError } from './claude-route-errors.js';

const ANTHROPIC_API_VERSION = '2023-06-01';
const ANTHROPIC_ORGANIZATION_HEADER = 'anthropic-organization-id';
const ANTHROPIC_WORKSPACE_HEADER = 'anthropic-workspace-id';

export const CLAUDE_CREDENTIAL_PARAMETER_ROOT = '/folklore/prod';
export const CLAUDE_CREDENTIAL_PARAMETER_SUFFIX = '/provider-inference/anthropic-api-key';
export const CLAUDE_CREDENTIAL_KEY_ALIAS = 'alias/folklore-prod-anthropic-credential';

export const claudeCredentialLoadErrors: AttestedParameterReadErrors = {
  missing: 'claude_credential_missing',
  accessDenied: 'claude_credential_access_denied',
  identity: 'claude_credential_identity_invalid',
  version: 'claude_credential_version_invalid',
  value: 'claude_credential_value_invalid',
  decrypt: 'claude_credential_decrypt_failed',
};

const PREFLIGHT_TIMEOUT_MS = 10_000;
const MAX_KEY_BYTES = 256;
const KEY_SHAPE = /^sk-ant-[A-Za-z0-9_-]{20,200}$/;
const HTTP_OK = 200;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
export const CLAUDE_WORKSPACE_HEADER_UNEXPECTED = 'claude_workspace_header_unexpected';

export type ClaudeCredentialManifest = ProviderKeyManifest;

export interface ClaudeCredentialDeps {
  readonly reader: Pick<AttestedSsmParameterReader, 'read'>;
  readonly manifest: () => ClaudeCredentialManifest | undefined;
  readonly expected: {
    readonly organizationIdSha256: string;
    readonly workspaceIdSha256: string;
  };
  readonly allowedModels: readonly ClaudeModelId[];
  readonly transport: AnthropicTransport;
  readonly onAlarm?: (code: string) => void;
  readonly now?: () => number;
}

/** The Anthropic key, read only through the attested reader and bound to the compiled org hash before use. */
export class ClaudeCredentialSource {
  private readonly holder: ProviderKeyHolder;
  private readonly keyReader: AttestedProviderKeyReader;

  constructor(private readonly deps: ClaudeCredentialDeps) {
    this.keyReader = new AttestedProviderKeyReader(
      {
        parameterPath: `${CLAUDE_CREDENTIAL_PARAMETER_ROOT}${CLAUDE_CREDENTIAL_PARAMETER_SUFFIX}`,
        keyAlias: CLAUDE_CREDENTIAL_KEY_ALIAS,
        keyShape: KEY_SHAPE,
        maxKeyBytes: MAX_KEY_BYTES,
        unavailable: () => new ClaudeRouteError('claude_credential_unavailable'),
      },
      deps,
    );
    this.holder = new ProviderKeyHolder({
      load: () => this.load(),
      heldError: (reason) =>
        new ClaudeRouteError(
          reason === 'rejected' ? 'claude_credential_rejected' : 'claude_credential_unavailable',
        ),
      ...(deps.now === undefined ? {} : { now: deps.now }),
    });
  }

  key(): Promise<string> {
    return this.holder.key();
  }

  invalidate(reason: KeyInvalidation): void {
    this.holder.invalidate(reason);
  }

  private async load(): Promise<Buffer> {
    const bytes = await this.keyReader.read();
    try {
      await this.preflight(bytes.toString('utf8'));
    } catch (error) {
      bytes.fill(0);
      throw error;
    }
    return bytes;
  }

  private async preflight(key: string): Promise<void> {
    const model = this.deps.allowedModels[0];
    if (model === undefined) throw new ClaudeRouteError('claude_credential_unavailable');
    const response = await this.deps.transport
      .fetch(`${ANTHROPIC_ORIGIN}${ANTHROPIC_MODELS_PATH_PREFIX}${model}`, {
        method: 'GET',
        headers: { 'x-api-key': key, 'anthropic-version': ANTHROPIC_API_VERSION },
        signal: AbortSignal.timeout(PREFLIGHT_TIMEOUT_MS),
      })
      .catch((error: unknown) => {
        throw this.preflightFailure(error);
      });
    await response.body?.cancel().catch(() => undefined);
    this.assertPreflightStatus(response.status);
    this.assertBound(response.headers);
    this.alarmOnUnexpectedWorkspace(response.headers);
  }

  private preflightFailure(error: unknown): ClaudeRouteError {
    const failure = transportFailureOf(error);
    return failure === undefined || failure === UPSTREAM_TIMEOUT_CAUSE
      ? new ClaudeRouteError('claude_credential_unavailable')
      : new ClaudeRouteError(failure);
  }

  private alarmOnUnexpectedWorkspace(headers: Pick<Headers, 'get'>): void {
    if (this.deps.expected.workspaceIdSha256 !== '') return;
    if (headers.get(ANTHROPIC_WORKSPACE_HEADER) === null) return;
    this.deps.onAlarm?.(CLAUDE_WORKSPACE_HEADER_UNEXPECTED);
  }

  private assertPreflightStatus(status: number): void {
    if (status === HTTP_UNAUTHORIZED || status === HTTP_FORBIDDEN) {
      this.invalidate('rejected');
      throw new ClaudeRouteError('claude_credential_rejected');
    }
    if (status !== HTTP_OK) throw new ClaudeRouteError('claude_credential_unavailable');
  }

  private assertBound(headers: Pick<Headers, 'get'>): void {
    const mismatch = claudeIdentityMismatch(headers, this.deps.expected);
    if (mismatch === undefined) return;
    this.invalidate('mismatch');
    throw new ClaudeRouteError(mismatch);
  }
}

export function claudeIdentityMismatch(
  headers: Pick<Headers, 'get'>,
  expected: { readonly organizationIdSha256: string; readonly workspaceIdSha256: string },
): 'claude_organization_mismatch' | 'claude_workspace_mismatch' | undefined {
  const organization = headers.get(ANTHROPIC_ORGANIZATION_HEADER);
  if (organization === null || sha256Hex(organization) !== expected.organizationIdSha256) {
    return 'claude_organization_mismatch';
  }
  if (expected.workspaceIdSha256 === '') return undefined;
  const workspace = headers.get(ANTHROPIC_WORKSPACE_HEADER);
  return workspace !== null && sha256Hex(workspace) === expected.workspaceIdSha256
    ? undefined
    : 'claude_workspace_mismatch';
}
