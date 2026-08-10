import { GetParameterCommand, PutParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';

const CAPTURE_WINDOW_MS = 10 * 60 * 1000;

export interface NotionVerificationCaptureConfig {
  captureUntilParameter: string;
  pendingTokenParameter: string;
  kmsKeyId: string;
}

export type NotionCaptureResult = 'captured' | 'disabled' | 'occupied' | 'unavailable';

export function getNotionVerificationCaptureConfig(
  env: Record<string, string | undefined> = process.env,
): NotionVerificationCaptureConfig | null {
  const captureUntilParameter = env['NOTION_CAPTURE_UNTIL_PARAMETER'];
  const pendingTokenParameter = env['NOTION_PENDING_TOKEN_PARAMETER'];
  const kmsKeyId = env['NOTION_CAPTURE_KMS_KEY_ID'];
  if (!captureUntilParameter || !pendingTokenParameter || !kmsKeyId) return null;

  return { captureUntilParameter, pendingTokenParameter, kmsKeyId };
}

export function isNotionVerificationChallenge(
  body: unknown,
): body is { verification_token: string } {
  if (body === null || typeof body !== 'object') return false;

  const record = body as Record<string, unknown>;
  const token = record['verification_token'];
  return (
    !Array.isArray(body) &&
    Object.keys(record).length === 1 &&
    typeof token === 'string' &&
    token.length > 0 &&
    token.length <= 1024
  );
}

function isParameterNotFound(error: unknown): boolean {
  return error instanceof Error && error.name === 'ParameterNotFound';
}

function isParameterAlreadyExists(error: unknown): boolean {
  return error instanceof Error && error.name === 'ParameterAlreadyExists';
}

function isActiveCaptureWindow(marker: unknown, now: Date): boolean {
  if (typeof marker !== 'string') return false;
  const expiresAt = Date.parse(marker);
  const currentTime = now.getTime();
  return (
    Number.isFinite(expiresAt) &&
    Number.isFinite(currentTime) &&
    currentTime < expiresAt &&
    expiresAt <= currentTime + CAPTURE_WINDOW_MS
  );
}

export async function captureNotionVerificationToken(
  ssm: Pick<SSMClient, 'send'>,
  config: NotionVerificationCaptureConfig | null,
  token: string,
  getNow: () => Date,
): Promise<NotionCaptureResult> {
  if (!config) return 'disabled';

  let marker: string | undefined;
  try {
    const result = await ssm.send(
      new GetParameterCommand({ Name: config.captureUntilParameter, WithDecryption: false }),
    );
    marker = result.Parameter?.Value;
  } catch (error) {
    return isParameterNotFound(error) ? 'disabled' : 'unavailable';
  }

  if (!isActiveCaptureWindow(marker, getNow())) return 'disabled';

  try {
    await ssm.send(
      new PutParameterCommand({
        Name: config.pendingTokenParameter,
        Type: 'SecureString',
        KeyId: config.kmsKeyId,
        Value: token,
        Overwrite: false,
      }),
    );
    return 'captured';
  } catch (error) {
    return isParameterAlreadyExists(error) ? 'occupied' : 'unavailable';
  }
}
