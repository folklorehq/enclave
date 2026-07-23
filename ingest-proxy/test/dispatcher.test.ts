import { createHmac } from 'crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockSsmSend, mockLambdaSend, mockDdbSend } = vi.hoisted(() => ({
  mockSsmSend: vi.fn(),
  mockLambdaSend: vi.fn(async () => ({ $metadata: {} })),
  mockDdbSend: vi.fn(async () => ({ $metadata: {} })),
}));

vi.mock('@aws-sdk/client-ssm', () => ({
  SSMClient: vi.fn(() => ({ send: mockSsmSend })),
  GetParameterCommand: vi.fn((input: unknown) => input),
}));

vi.mock('@aws-sdk/client-lambda', () => ({
  LambdaClient: vi.fn(() => ({ send: mockLambdaSend })),
  InvokeCommand: vi.fn((input: unknown) => input),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn(() => ({ send: mockDdbSend })),
  GetItemCommand: vi.fn((input: unknown) => input),
}));

process.env['WEBHOOK_ROUTING_TABLE'] = 'test-routing-table';

const DISPATCHER_SECRET = 'test-dispatcher-secret';
const DISPATCHER_SECRET_PARAM = '/folklore/shared/dispatcher-auth-secret';
const TEST_TENANT = 'tenant-abc';
const TEST_SOURCE = 'github';

function githubSig(body: string, secret: string) {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

function expectedAuthHmac(tenantId: string, source: string, secret: string) {
  return createHmac('sha256', secret).update(`${tenantId}:${source}`).digest('hex');
}

function makeEvent(tenantId: string | undefined, source: string, body: string, headers = {}) {
  return {
    pathParameters: tenantId ? { tenant_id: tenantId, source } : { source },
    headers,
    body,
  };
}

// dispatcher-auth.ts and tenant-resolver.ts both cache module-scoped state keyed independently
// of the mock reset below; a fresh module import per test keeps those caches from leaking
// across tests (same reasoning as the sibling cache-isolation tests in handler.test.ts).
beforeEach(() => {
  vi.resetModules();
  mockLambdaSend.mockClear();
  mockDdbSend.mockClear();
});

describe('dispatcher — URL-routed (per-tenant) mode', () => {
  const PER_TENANT_SECRET = 'per-tenant-webhook-secret';

  function mockSsm(dispatcherSecretAvailable: boolean) {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name === `/folklore/${TEST_TENANT}/webhook-secrets/${TEST_SOURCE}`) {
        return { Parameter: { Value: PER_TENANT_SECRET } };
      }
      if (cmd.Name === DISPATCHER_SECRET_PARAM && dispatcherSecretAvailable) {
        return { Parameter: { Value: DISPATCHER_SECRET } };
      }
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });
  }

  it('invokes the per-tenant ingest Lambda with a correctly-computed authHmac', async () => {
    mockSsm(true);
    const { handler } = await import('../src/dispatcher.js');
    const body = JSON.stringify({ action: 'push' });
    const event = makeEvent(TEST_TENANT, TEST_SOURCE, body, {
      'x-hub-signature-256': githubSig(body, PER_TENANT_SECRET),
      'x-github-event': 'push',
    });

    const result = await handler(event as never, {} as never, vi.fn());

    expect(result).toMatchObject({ statusCode: 200 });
    expect(mockLambdaSend).toHaveBeenCalledTimes(1);
    const invoke = mockLambdaSend.mock.calls[0]![0] as {
      FunctionName: string;
      Payload: Buffer;
    };
    expect(invoke.FunctionName).toBe(`${TEST_TENANT}-ingest`);
    const payload = JSON.parse(invoke.Payload.toString()) as Record<string, unknown>;
    expect(payload['authHmac']).toBe(expectedAuthHmac(TEST_TENANT, TEST_SOURCE, DISPATCHER_SECRET));
    // Regression guard: the pre-fix URL-routed path omitted authHmac, headers, and
    // eventType from the invoke payload entirely — the receiver requires all three.
    expect(payload['eventType']).toBe('push');
    expect(payload['headers']).toMatchObject({ 'x-github-event': 'push' });
  });

  it('fails closed (503) and never invokes the ingest Lambda when the dispatcher-auth secret is unprovisioned', async () => {
    mockSsm(false);
    const { handler } = await import('../src/dispatcher.js');
    const body = JSON.stringify({ action: 'push' });
    const event = makeEvent(TEST_TENANT, TEST_SOURCE, body, {
      'x-hub-signature-256': githubSig(body, PER_TENANT_SECRET),
    });

    const result = await handler(event as never, {} as never, vi.fn());

    expect(result).toMatchObject({ statusCode: 503 });
    expect(mockLambdaSend).not.toHaveBeenCalled();
  });

  it('returns 401 and never invokes the ingest Lambda when the webhook signature is invalid', async () => {
    mockSsm(true);
    const { handler } = await import('../src/dispatcher.js');
    const body = JSON.stringify({ action: 'push' });
    const event = makeEvent(TEST_TENANT, TEST_SOURCE, body, {
      'x-hub-signature-256': githubSig(body, 'wrong-secret'),
    });

    const result = await handler(event as never, {} as never, vi.fn());

    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockLambdaSend).not.toHaveBeenCalled();
  });

  it('returns 500 instead of throwing when the downstream Lambda invoke rejects', async () => {
    mockSsm(true);
    mockLambdaSend.mockRejectedValueOnce(new Error('Lambda service unavailable'));
    const { handler } = await import('../src/dispatcher.js');
    const body = JSON.stringify({ action: 'push' });
    const event = makeEvent(TEST_TENANT, TEST_SOURCE, body, {
      'x-hub-signature-256': githubSig(body, PER_TENANT_SECRET),
    });

    const result = await handler(event as never, {} as never, vi.fn());

    expect(result).toMatchObject({ statusCode: 500 });
  });
});

describe('dispatcher — shared-secret mode', () => {
  const SHARED_SECRET = 'shared-github-app-secret';
  const INSTALLATION_ID = '99887766';

  function mockSsm(dispatcherSecretAvailable: boolean) {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name === `/folklore/shared-webhook-secrets/${TEST_SOURCE}`) {
        return { Parameter: { Value: SHARED_SECRET } };
      }
      if (cmd.Name === DISPATCHER_SECRET_PARAM && dispatcherSecretAvailable) {
        return { Parameter: { Value: DISPATCHER_SECRET } };
      }
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });
  }

  function mockRoutingEntry() {
    mockDdbSend.mockImplementation(async () => ({
      Item: { orgId: { S: TEST_TENANT }, functionName: { S: '' } },
    }));
  }

  it('resolves the tenant, invokes its ingest Lambda, and signs the invoke with authHmac', async () => {
    mockSsm(true);
    mockRoutingEntry();
    const { handler } = await import('../src/dispatcher.js');
    const body = JSON.stringify({ action: 'push', installation: { id: INSTALLATION_ID } });
    const event = makeEvent(undefined, TEST_SOURCE, body, {
      'x-hub-signature-256': githubSig(body, SHARED_SECRET),
    });

    const result = await handler(event as never, {} as never, vi.fn());

    expect(result).toMatchObject({ statusCode: 200 });
    expect(mockLambdaSend).toHaveBeenCalledTimes(1);
    const invoke = mockLambdaSend.mock.calls[0]![0] as { Payload: Buffer };
    const payload = JSON.parse(invoke.Payload.toString()) as Record<string, string>;
    expect(payload['tenantId']).toBe(TEST_TENANT);
    expect(payload['authHmac']).toBe(expectedAuthHmac(TEST_TENANT, TEST_SOURCE, DISPATCHER_SECRET));
  });

  it('fails closed (503) when the dispatcher-auth secret is unprovisioned, even with a valid signature and resolved tenant', async () => {
    mockSsm(false);
    mockRoutingEntry();
    const { handler } = await import('../src/dispatcher.js');
    const body = JSON.stringify({ action: 'push', installation: { id: INSTALLATION_ID } });
    const event = makeEvent(undefined, TEST_SOURCE, body, {
      'x-hub-signature-256': githubSig(body, SHARED_SECRET),
    });

    const result = await handler(event as never, {} as never, vi.fn());

    expect(result).toMatchObject({ statusCode: 503 });
    expect(mockLambdaSend).not.toHaveBeenCalled();
  });
});
