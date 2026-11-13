import { sha256Hex } from '@folklore/utils';
import type {
  AttestedParameterReadErrors,
  AttestedSsmParameterReader,
} from '../../attestation/AttestedSsmParameterReader.js';
import {
  TYPESAFE_MODELS_PATH,
  TYPESAFE_ORIGIN,
  type TypeSafeTransport,
} from '../../egress/typesafe-transport.js';
import {
  TYPESAFE_UPSTREAM_TIMEOUT_CAUSE,
  typesafeTransportFailureOf,
} from '../../egress/typesafe-transport-failure.js';
import {
  AttestedProviderKeyReader,
  type ProviderKeyManifest,
} from '../credentials/AttestedProviderKeyReader.js';
import { ProviderKeyHolder, type KeyInvalidation } from '../credentials/ProviderKeyHolder.js';
import { TYPESAFE_KEY_BINDING_DOMAIN } from './typesafe-decision-route-config.js';
import { TypeSafeDecisionError } from './typesafe-decision-errors.js';
import { mapTypeSafeTransportError } from './typesafe-error-map.js';

export const TYPESAFE_CREDENTIAL_PARAMETER_ROOT = '/folklore/prod';
export const TYPESAFE_CREDENTIAL_PARAMETER_SUFFIX = '/provider-inference/typesafe-api-key';
export const TYPESAFE_CREDENTIAL_KEY_ALIAS = 'alias/folklore-prod-typesafe-credential';

export const typesafeCredentialLoadErrors: AttestedParameterReadErrors = {
  missing: 'typesafe_credential_missing',
  accessDenied: 'typesafe_credential_access_denied',
  identity: 'typesafe_credential_identity_invalid',
  version: 'typesafe_credential_version_invalid',
  value: 'typesafe_credential_value_invalid',
  decrypt: 'typesafe_credential_decrypt_failed',
};

const PREFLIGHT_TIMEOUT_MS = 10_000;
const MAX_KEY_BYTES = 300;
const KEY_SHAPE = /^[\x21-\x7e]{32,256}$/;
const HTTP_OK = 200;
const HTTP_UNAUTHORIZED = 401;
const BINDING_MISMATCH_ALARM = 'typesafe_credential_binding_mismatch';

export function typesafeKeyBinding(key: string): string {
  return sha256Hex(`${TYPESAFE_KEY_BINDING_DOMAIN}\n${key}`);
}

export interface TypeSafeCredentialDeps {
  readonly reader: Pick<AttestedSsmParameterReader, 'read'>;
  readonly manifest: () => ProviderKeyManifest | undefined;
  readonly expectedBinding: string;
  readonly transport: TypeSafeTransport;
  readonly onAlarm?: (code: string) => void;
  readonly now?: () => number;
}

/** The TypeSafe key, read only through the attested reader and bound to the compiled hash before use. */
export class TypeSafeCredentialSource {
  private readonly holder: ProviderKeyHolder;
  private readonly keyReader: AttestedProviderKeyReader;

  constructor(private readonly deps: TypeSafeCredentialDeps) {
    this.keyReader = new AttestedProviderKeyReader(
      {
        parameterPath: `${TYPESAFE_CREDENTIAL_PARAMETER_ROOT}${TYPESAFE_CREDENTIAL_PARAMETER_SUFFIX}`,
        keyAlias: TYPESAFE_CREDENTIAL_KEY_ALIAS,
        keyShape: KEY_SHAPE,
        maxKeyBytes: MAX_KEY_BYTES,
        unavailable: () => new TypeSafeDecisionError('typesafe_credential_unavailable'),
      },
      deps,
    );
    this.holder = new ProviderKeyHolder({
      load: () => this.load(),
      heldError: (reason) =>
        new TypeSafeDecisionError(
          reason === 'rejected'
            ? 'typesafe_credential_rejected'
            : 'typesafe_credential_binding_mismatch',
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
      const key = bytes.toString('utf8');
      this.assertBound(key);
      await this.preflight(key);
    } catch (error) {
      bytes.fill(0);
      throw error;
    }
    return bytes;
  }

  private assertBound(key: string): void {
    if (typesafeKeyBinding(key) === this.deps.expectedBinding) return;
    this.invalidate('mismatch');
    this.deps.onAlarm?.(BINDING_MISMATCH_ALARM);
    throw new TypeSafeDecisionError('typesafe_credential_binding_mismatch');
  }

  private async preflight(key: string): Promise<void> {
    const response = await this.deps.transport
      .fetch(`${TYPESAFE_ORIGIN}${TYPESAFE_MODELS_PATH}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${key}` },
        signal: AbortSignal.timeout(PREFLIGHT_TIMEOUT_MS),
      })
      .catch((error: unknown) => {
        throw this.preflightFailure(error);
      });
    await response.body?.cancel().catch(() => undefined);
    this.assertPreflightStatus(response.status);
  }

  private preflightFailure(error: unknown): TypeSafeDecisionError {
    const failure = typesafeTransportFailureOf(error);
    return failure === undefined || failure === TYPESAFE_UPSTREAM_TIMEOUT_CAUSE
      ? new TypeSafeDecisionError('typesafe_credential_unavailable')
      : mapTypeSafeTransportError(error, this.alarm());
  }

  private alarm(): { readonly onAlarm?: (code: string) => void } {
    const { onAlarm } = this.deps;
    return onAlarm === undefined ? {} : { onAlarm };
  }

  private assertPreflightStatus(status: number): void {
    if (status === HTTP_UNAUTHORIZED) {
      this.invalidate('rejected');
      throw new TypeSafeDecisionError('typesafe_credential_rejected');
    }
    if (status !== HTTP_OK) throw new TypeSafeDecisionError('typesafe_credential_unavailable');
  }
}
