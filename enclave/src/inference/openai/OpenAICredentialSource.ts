import { sha256Hex } from '@folklore/utils';
import type {
  AttestedParameterReadErrors,
  AttestedSsmParameterReader,
} from '../../attestation/AttestedSsmParameterReader.js';
import {
  OPENAI_EMBEDDINGS_PATH,
  OPENAI_MODEL_PATH,
  OPENAI_ORIGIN,
  type OpenAITransport,
} from '../../egress/openai-transport.js';
import {
  AttestedProviderKeyReader,
  type ProviderKeyManifest,
} from '../credentials/AttestedProviderKeyReader.js';
import { ProviderKeyHolder, type KeyInvalidation } from '../credentials/ProviderKeyHolder.js';
import { OpenAIEmbedRouteError } from './openai-embed-errors.js';
import {
  OPENAI_UPSTREAM_TIMEOUT_CAUSE,
  openaiTransportFailureOf,
} from '../../egress/openai-transport-failure.js';
import { mapOpenAITransportError } from './openai-error-map.js';
import { OPENAI_EMBED_DIMENSIONS, OPENAI_EMBED_MODEL } from './openai-embed-route-state.js';

const OPENAI_ORGANIZATION_HEADER = 'openai-organization';
const OPENAI_PROJECT_HEADER = 'openai-project';
const PROBE_INPUT = 'folklore embedding probe';

export const OPENAI_CREDENTIAL_PARAMETER_ROOT = '/folklore/prod';
export const OPENAI_CREDENTIAL_PARAMETER_SUFFIX = '/provider-inference/openai-api-key';
export const OPENAI_CREDENTIAL_KEY_ALIAS = 'alias/folklore-prod-openai-credential';

export const openaiCredentialLoadErrors: AttestedParameterReadErrors = {
  missing: 'openai_credential_missing',
  accessDenied: 'openai_credential_access_denied',
  identity: 'openai_credential_identity_invalid',
  version: 'openai_credential_version_invalid',
  value: 'openai_credential_value_invalid',
  decrypt: 'openai_credential_decrypt_failed',
};

const PREFLIGHT_TIMEOUT_MS = 10_000;
const MAX_KEY_BYTES = 300;
const KEY_SHAPE = /^sk-(?!ant-)(proj-)?[A-Za-z0-9_-]{20,250}$/;
const HTTP_OK = 200;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;

export type OpenAICredentialManifest = ProviderKeyManifest;

export interface OpenAIExpectedIdentity {
  readonly organizationIdSha256: string;
  readonly projectIdSha256: string;
}

export interface OpenAICredentialDeps {
  readonly reader: Pick<AttestedSsmParameterReader, 'read'>;
  readonly manifest: () => OpenAICredentialManifest | undefined;
  readonly expected: OpenAIExpectedIdentity;
  readonly transport: OpenAITransport;
  readonly onAlarm?: (code: string) => void;
  readonly now?: () => number;
}

/** The OpenAI key, read only through the attested reader and bound to the compiled identity before use. */
export class OpenAICredentialSource {
  private readonly holder: ProviderKeyHolder;
  private readonly keyReader: AttestedProviderKeyReader;

  constructor(private readonly deps: OpenAICredentialDeps) {
    this.keyReader = new AttestedProviderKeyReader(
      {
        parameterPath: `${OPENAI_CREDENTIAL_PARAMETER_ROOT}${OPENAI_CREDENTIAL_PARAMETER_SUFFIX}`,
        keyAlias: OPENAI_CREDENTIAL_KEY_ALIAS,
        keyShape: KEY_SHAPE,
        maxKeyBytes: MAX_KEY_BYTES,
        unavailable: () => new OpenAIEmbedRouteError('openai_credential_unavailable'),
      },
      deps,
    );
    this.holder = new ProviderKeyHolder({
      load: () => this.load(),
      heldError: (reason) =>
        new OpenAIEmbedRouteError(
          reason === 'rejected' ? 'openai_credential_rejected' : 'openai_credential_unavailable',
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
    let response = await this.send(`${OPENAI_ORIGIN}${OPENAI_MODEL_PATH}`, {
      method: 'GET',
      headers: { authorization: `Bearer ${key}` },
    });
    if (this.needsProbe(response)) {
      await response.body?.cancel().catch(() => undefined);
      response = await this.send(...this.probeRequest(key));
    }
    await response.body?.cancel().catch(() => undefined);
    this.assertPreflightStatus(response.status);
    this.assertBound(response.headers);
  }

  // The model lookup is served from an edge cache that omits the identity headers, so an absent one takes the probe too.
  private needsProbe(response: Response): boolean {
    if (response.status === HTTP_FORBIDDEN) return true;
    return response.status === HTTP_OK && response.headers.get(OPENAI_ORGANIZATION_HEADER) === null;
  }

  // A restricted key may lack model-read permission; a fixed public input proves it still embeds.
  private probeRequest(key: string): [string, RequestInit] {
    return [
      `${OPENAI_ORIGIN}${OPENAI_EMBEDDINGS_PATH}`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${key}`,
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: JSON.stringify({
          model: OPENAI_EMBED_MODEL,
          input: PROBE_INPUT,
          dimensions: OPENAI_EMBED_DIMENSIONS,
          encoding_format: 'float',
        }),
      },
    ];
  }

  private send(url: string, init: RequestInit): Promise<Response> {
    return this.deps.transport
      .fetch(url, { ...init, signal: AbortSignal.timeout(PREFLIGHT_TIMEOUT_MS) })
      .catch((error: unknown) => {
        throw this.preflightFailure(error);
      });
  }

  private preflightFailure(error: unknown): OpenAIEmbedRouteError {
    const failure = openaiTransportFailureOf(error);
    return failure === undefined || failure === OPENAI_UPSTREAM_TIMEOUT_CAUSE
      ? new OpenAIEmbedRouteError('openai_credential_unavailable')
      : mapOpenAITransportError(error, this.alarm());
  }

  private alarm(): { readonly onAlarm?: (code: string) => void } {
    const { onAlarm } = this.deps;
    return onAlarm === undefined ? {} : { onAlarm };
  }

  private assertPreflightStatus(status: number): void {
    if (status === HTTP_UNAUTHORIZED) {
      this.invalidate('rejected');
      throw new OpenAIEmbedRouteError('openai_credential_rejected');
    }
    if (status !== HTTP_OK) throw new OpenAIEmbedRouteError('openai_credential_unavailable');
  }

  private assertBound(headers: Pick<Headers, 'get'>): void {
    const mismatch = openaiIdentityMismatch(headers, this.deps.expected);
    if (mismatch === undefined) return;
    this.invalidate('mismatch');
    throw new OpenAIEmbedRouteError(mismatch);
  }
}

export type OpenAIIdentityMismatch =
  | 'openai_organization_mismatch'
  | 'openai_project_mismatch'
  | 'openai_project_hash_required';

export function openaiIdentityMismatch(
  headers: Pick<Headers, 'get'>,
  expected: OpenAIExpectedIdentity,
): OpenAIIdentityMismatch | undefined {
  const organization = headers.get(OPENAI_ORGANIZATION_HEADER);
  if (organization === null || sha256Hex(organization) !== expected.organizationIdSha256) {
    return 'openai_organization_mismatch';
  }
  const project = headers.get(OPENAI_PROJECT_HEADER);
  if (project === null) {
    return expected.projectIdSha256 === '' ? undefined : 'openai_project_mismatch';
  }
  if (expected.projectIdSha256 === '') return 'openai_project_hash_required';
  return sha256Hex(project) === expected.projectIdSha256 ? undefined : 'openai_project_mismatch';
}
