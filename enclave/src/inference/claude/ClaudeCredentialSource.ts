import { createHash } from 'node:crypto';
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

const REFRESH_INTERVAL_MS = 60 * 60_000;
const REJECTED_REFRESH_MIN_MS = 60_000;
const PREFLIGHT_TIMEOUT_MS = 10_000;
const MAX_KEY_BYTES = 256;
const KEY_SHAPE = /^sk-ant-[A-Za-z0-9_-]{20,200}$/;
const HTTP_OK = 200;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
export const CLAUDE_WORKSPACE_HEADER_UNEXPECTED = 'claude_workspace_header_unexpected';

export type ClaudeCredentialManifest = Pick<
  VerifiedBootManifest,
  'awsAccountId' | 'awsRegion' | 'storageKeyArn' | 'enclaveOutputKeyKmsKeyArn'
>;

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

interface LoadedKey {
  readonly bytes: Buffer;
  readonly loadedAt: number;
}

interface Hold {
  readonly code: string;
  readonly at: number;
}

function sha256Of(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** The Anthropic key, read only through the attested reader and bound to the compiled org hash before use. */
export class ClaudeCredentialSource {
  private loaded: LoadedKey | undefined;
  private inflight: Promise<LoadedKey> | undefined;
  private hold: Hold | undefined;
  private readonly now: () => number;

  constructor(private readonly deps: ClaudeCredentialDeps) {
    this.now = deps.now ?? (() => Date.now());
  }

  async key(): Promise<string> {
    this.assertNotHeld();
    const current = this.loaded;
    if (current !== undefined && this.now() - current.loadedAt < REFRESH_INTERVAL_MS) {
      return current.bytes.toString('utf8');
    }
    const loaded = await (this.inflight ??= this.load().finally(() => {
      this.inflight = undefined;
    }));
    return loaded.bytes.toString('utf8');
  }

  invalidate(reason: 'rejected' | 'mismatch'): void {
    this.loaded?.bytes.fill(0);
    this.loaded = undefined;
    this.hold ??= {
      code: reason === 'rejected' ? 'claude_credential_rejected' : 'claude_credential_unavailable',
      at: this.now(),
    };
  }

  private assertNotHeld(): void {
    if (this.hold === undefined) return;
    if (this.now() - this.hold.at < REJECTED_REFRESH_MIN_MS)
      throw new ClaudeRouteError(this.hold.code);
    this.hold = undefined;
  }

  private async load(): Promise<LoadedKey> {
    const bytes = await this.readKey();
    try {
      await this.preflight(bytes.toString('utf8'));
    } catch (error) {
      bytes.fill(0);
      throw error;
    }
    this.loaded?.bytes.fill(0);
    this.loaded = { bytes, loadedAt: this.now() };
    return this.loaded;
  }

  private async readKey(): Promise<Buffer> {
    const plaintext = await this.deps.reader.read(this.signedRead()).catch(() => {
      throw new ClaudeRouteError('claude_credential_unavailable');
    });
    const key = Buffer.from(plaintext).toString('utf8');
    plaintext.fill(0);
    if (plaintext.length === 0 || plaintext.length > MAX_KEY_BYTES || !KEY_SHAPE.test(key)) {
      throw new ClaudeRouteError('claude_credential_unavailable');
    }
    return Buffer.from(key, 'utf8');
  }

  private signedRead(): AttestedParameterRead {
    const manifest = this.deps.manifest();
    const outputKey = manifest?.enclaveOutputKeyKmsKeyArn;
    if (!manifest || !outputKey || !manifest.awsAccountId || !manifest.awsRegion) {
      throw new ClaudeRouteError('claude_credential_unavailable');
    }
    return {
      path: `${CLAUDE_CREDENTIAL_PARAMETER_ROOT}${CLAUDE_CREDENTIAL_PARAMETER_SUFFIX}`,
      awsAccountId: manifest.awsAccountId,
      awsRegion: manifest.awsRegion,
      keyId: `arn:aws:kms:${manifest.awsRegion}:${manifest.awsAccountId}:${CLAUDE_CREDENTIAL_KEY_ALIAS}`,
      refusedKeyIds: [manifest.storageKeyArn, outputKey],
    };
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
  if (organization === null || sha256Of(organization) !== expected.organizationIdSha256) {
    return 'claude_organization_mismatch';
  }
  if (expected.workspaceIdSha256 === '') return undefined;
  const workspace = headers.get(ANTHROPIC_WORKSPACE_HEADER);
  return workspace !== null && sha256Of(workspace) === expected.workspaceIdSha256
    ? undefined
    : 'claude_workspace_mismatch';
}
