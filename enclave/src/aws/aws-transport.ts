import { fromInstanceMetadata } from '@smithy/credential-provider-imds';
import type { HttpsProxyAgent } from 'https-proxy-agent';
import { awsHttpsProxyAgent } from '../egress/proxy.js';

// Under the SDK's 6 s threshold, so the idle timer arms at once and also bounds the response body.
export const AWS_SOCKET_IDLE_TIMEOUT_MS = 5_000;
// Three times the longest SQS long poll (20 s); a one-write TLS upload to S3 also looks idle this long.
const AWS_LONG_SOCKET_IDLE_TIMEOUT_MS = 60_000;
const AWS_CONNECTION_TIMEOUT_MS = 10_000;

type AwsCredentialIdentityProvider = ReturnType<typeof fromInstanceMetadata>;
type AwsCredentials = Awaited<ReturnType<AwsCredentialIdentityProvider>>;

// The SDK default is 1000 ms and 0 retries, which the socat vsock relay outran under load.
export const IMDS_TIMEOUT_MS = 3_000;
export const IMDS_MAX_RETRIES = 3;

export interface AwsClientTransport {
  credentials: AwsCredentialIdentityProvider;
  requestHandler: {
    httpsAgent: HttpsProxyAgent<string>;
    connectionTimeout: number;
    socketTimeout: number;
  };
}

const EXPIRED_MARGIN_MS = 60_000;

function isUsable(credentials: AwsCredentials): boolean {
  return (
    credentials.expiration === undefined ||
    credentials.expiration.getTime() - Date.now() > EXPIRED_MARGIN_MS
  );
}

// The raw IMDS provider refetches per call; this reuses one result and one in-flight fetch.
function memoizeUntilExpiry(
  provider: AwsCredentialIdentityProvider,
): AwsCredentialIdentityProvider {
  let current: AwsCredentials | undefined;
  let inflight: Promise<AwsCredentials> | undefined;
  return async () => {
    if (current && isUsable(current)) return current;
    inflight ??= provider().finally(() => {
      inflight = undefined;
    });
    current = await inflight;
    return current;
  };
}

let sharedCredentials: AwsCredentialIdentityProvider | undefined;

export function awsCredentials(): AwsCredentialIdentityProvider {
  sharedCredentials ??= memoizeUntilExpiry(
    fromInstanceMetadata({ timeout: IMDS_TIMEOUT_MS, maxRetries: IMDS_MAX_RETRIES }),
  );
  return sharedCredentials;
}

// Tests need a fresh memo per fake IMDS server.
export function resetAwsCredentialsForTest(): void {
  sharedCredentials = undefined;
}

// SDK v3 uses node:http, not undici, so the global egress dispatcher misses it — hand the agent to
// the client, which builds its own NodeHttpHandler from these options (HttpHandlerUserInput).
export function awsClientTransport(socketTimeout: number): AwsClientTransport {
  return {
    credentials: awsCredentials(),
    requestHandler: {
      httpsAgent: awsHttpsProxyAgent(),
      connectionTimeout: AWS_CONNECTION_TIMEOUT_MS,
      socketTimeout,
    },
  };
}

export function awsShortCallTransport(): AwsClientTransport {
  return awsClientTransport(AWS_SOCKET_IDLE_TIMEOUT_MS);
}

// Long polls and one-write uploads look idle for far longer than a short call, so a 5 s bound would cut them.
export function awsLongCallTransport(): AwsClientTransport {
  return awsClientTransport(AWS_LONG_SOCKET_IDLE_TIMEOUT_MS);
}
