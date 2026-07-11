import { createHmac, generateKeyPairSync } from 'crypto';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// Hoist mock factories so they're available before vi.mock() calls
const { mockSsmSend, mockSqsSend } = vi.hoisted(() => ({
  mockSsmSend: vi.fn(),
  mockSqsSend: vi.fn(async () => ({ $metadata: {} })),
}));

vi.mock('@aws-sdk/client-ssm', () => ({
  SSMClient: vi.fn(() => ({ send: mockSsmSend })),
  GetParameterCommand: vi.fn((input: unknown) => input),
}));

vi.mock('@aws-sdk/client-sqs', () => ({
  SQSClient: vi.fn(() => ({ send: mockSqsSend })),
  SendMessageCommand: vi.fn((input: unknown) => input),
}));

process.env['QUEUE_URL'] = 'https://sqs.test/queue';

const { handler } = await import('../src/handler.js');

// A real X25519 key pair to serve as the "tenant" recipient key
const { publicKey: testRecipientPub } = generateKeyPairSync('x25519');
const testPubBytes = Buffer.from(
  testRecipientPub.export({ type: 'spki', format: 'der' }).slice(-32),
);
const testPubHex = testPubBytes.toString('hex');

const TEST_SECRET = 'test-webhook-secret-abc123';

function makeEvent(
  tenantId: string,
  source: string,
  body: string,
  headers: Record<string, string> = {},
) {
  return {
    pathParameters: { tenant_id: tenantId, source },
    headers,
    body,
  };
}

function githubSig(body: string, secret: string) {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

function slackSig(body: string, secret: string, ts: string) {
  const base = `v0:${ts}:${body}`;
  return 'v0=' + createHmac('sha256', secret).update(base).digest('hex');
}

function linearSig(body: string, secret: string) {
  return createHmac('sha256', secret).update(body).digest('hex');
}

function intercomSig(body: string, secret: string) {
  return 'sha1=' + createHmac('sha1', secret).update(body).digest('hex');
}

function notionSig(body: string, secret: string) {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

function meetingSig(body: string, secret: string) {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

beforeAll(() => {
  // Default: public key lookup succeeds, HMAC secret lookup throws (no secret provisioned)
  mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
    if (cmd.Name?.endsWith('/ingest-public-key')) {
      return { Parameter: { Value: testPubHex } };
    }
    throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
  });
});

beforeEach(() => {
  mockSqsSend.mockClear();
});

describe('path parameter validation', () => {
  it('returns 400 when tenant_id is missing', async () => {
    const event = { pathParameters: { source: 'github' }, headers: {}, body: '' };
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 400 });
  });

  it('returns 400 when source is missing', async () => {
    const event = { pathParameters: { tenant_id: 'tenant1' }, headers: {}, body: '' };
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 400 });
  });

  it('returns 400 when pathParameters is absent', async () => {
    const event = { headers: {}, body: '' };
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 400 });
  });
});

describe('HMAC signature verification — GitHub', () => {
  const tid = 'tenant-gh';
  const body = JSON.stringify({ action: 'opened', number: 5 });

  it('returns 200 when signature is valid', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/github'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'github', body, {
      'x-github-event': 'pull_request',
      'x-hub-signature-256': githubSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('returns 401 when signature is wrong', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/github'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'github', body, {
      'x-github-event': 'pull_request',
      'x-hub-signature-256': githubSig(body, 'wrong-secret'),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });
});

describe('HMAC signature verification — Slack', () => {
  const tid = 'tenant-sl';
  const body = JSON.stringify({ type: 'message' });
  const freshTs = String(Math.floor(Date.now() / 1000));
  const staleTs = String(Math.floor(Date.now() / 1000) - 400);

  it('returns 200 when v0 signature is valid with fresh timestamp', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/slack'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'slack', body, {
      'x-slack-signature': slackSig(body, TEST_SECRET, freshTs),
      'x-slack-request-timestamp': freshTs,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('returns 401 on replay attack (timestamp > 5 min old)', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/slack'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'slack', body, {
      'x-slack-signature': slackSig(body, TEST_SECRET, staleTs),
      'x-slack-request-timestamp': staleTs,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });
});

describe('HMAC signature verification — Linear', () => {
  const tid = 'tenant-li';
  const body = JSON.stringify({ type: 'Issue', action: 'create' });

  it('returns 200 when hex signature is valid', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/linear'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'linear', body, {
      'linear-signature': linearSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });
});

describe('HMAC signature verification — Intercom', () => {
  const tid = 'tenant-ic';
  const body = JSON.stringify({ type: 'notification_event', topic: 'conversation.user.created' });

  it('returns 200 when sha1 signature is valid', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/intercom'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'intercom', body, {
      'x-hub-signature': intercomSig(body, TEST_SECRET),
      'x-intercom-topic': 'conversation.user.created',
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });
});

describe('HMAC signature verification — Notion', () => {
  const tid = 'tenant-no';
  const body = JSON.stringify({ type: 'page.created', page: { id: 'p1' } });

  it('returns 200 when sha256 signature is valid', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/notion'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'notion', body, {
      'x-notion-signature': notionSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('returns 401 when signature is wrong', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/notion'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'notion', body, {
      'x-notion-signature': notionSig(body, 'wrong-secret'),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 (fail closed) when no secret is configured', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });

    const event = makeEvent('tenant-no-open', 'notion', body, {
      'x-notion-signature': notionSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

describe('HMAC signature verification — Meeting', () => {
  const tid = 'tenant-me';
  const body = JSON.stringify({ meetingId: 'm1', title: 'Standup' });

  it('returns 200 when sha256 signature is valid', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/meeting'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'meeting', body, {
      'x-meeting-event': 'fireflies_complete',
      'x-meeting-signature': meetingSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('returns 401 when signature is wrong', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/meeting'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'meeting', body, {
      'x-meeting-event': 'fireflies_complete',
      'x-meeting-signature': meetingSig(body, 'wrong-secret'),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 (fail closed) when no secret is configured', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });

    const event = makeEvent('tenant-me-open', 'meeting', body, {
      'x-meeting-event': 'fireflies_complete',
      'x-meeting-signature': meetingSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

describe('fail closed when no secret configured', () => {
  it('returns 401 and does not send to SQS when ParameterNotFound for secret', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });

    const event = makeEvent('tenant-fo', 'notion', JSON.stringify({ type: 'page.created' }), {});
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

describe('unknown source rejection', () => {
  it('returns 400 for an unsupported source before any crypto work', async () => {
    const event = makeEvent('tenant-unk', 'pagerduty', JSON.stringify({ type: 'incident' }), {});
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 400 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

describe('transient SSM error on secret lookup', () => {
  it('returns 503 (retryable), not 401 or 200, and does not send to SQS', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('rate exceeded'), { name: 'ThrottlingException' });
    });

    const body = JSON.stringify({ type: 'page.created' });
    const event = makeEvent('tenant-transient', 'notion', body, {
      'x-notion-signature': notionSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 503 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

describe('SQS message shape', () => {
  it('sends message with correct tenant, source, and encrypted fields', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/github'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const body = JSON.stringify({ action: 'push' });
    const event = makeEvent('tenant-shape', 'github', body, {
      'x-github-event': 'push',
      'x-hub-signature-256': githubSig(body, TEST_SECRET),
    });
    await handler(event as never, {} as never, vi.fn());

    expect(mockSqsSend).toHaveBeenCalledOnce();
    const msg = mockSqsSend.mock.calls[0]![0] as Record<string, unknown>;
    const payload = JSON.parse(msg['MessageBody'] as string) as Record<string, string>;

    expect(payload['tenant_id']).toBe('tenant-shape');
    expect(payload['source']).toBe('github');
    expect(payload['eventType']).toBe('push');
    expect(payload['ephemeralPublicKey']).toMatch(/^[0-9a-f]{64}$/);
    expect(payload['nonce']).toMatch(/^[0-9a-f]{24}$/);
    expect(typeof payload['ciphertext']).toBe('string');
    expect((payload['ciphertext'] as string).length).toBeGreaterThan(0);
    expect(msg['MessageGroupId']).toBe('tenant-shape');
  });
});

describe('event type extraction', () => {
  beforeEach(() => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/')) return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });
  });

  it('extracts github event type from x-github-event header', async () => {
    const body = '{}';
    const event = makeEvent('tenant-et1', 'github', body, {
      'x-github-event': 'issues',
      'x-hub-signature-256': githubSig(body, TEST_SECRET),
    });
    await handler(event as never, {} as never, vi.fn());
    const msg = mockSqsSend.mock.calls[0]![0] as Record<string, unknown>;
    const payload = JSON.parse(msg['MessageBody'] as string) as Record<string, string>;
    expect(payload['eventType']).toBe('issues');
  });

  it('extracts slack event type from JSON body', async () => {
    const body = JSON.stringify({ type: 'app_mention' });
    const ts = String(Math.floor(Date.now() / 1000));
    const event = makeEvent('tenant-et2', 'slack', body, {
      'x-slack-signature': slackSig(body, TEST_SECRET, ts),
      'x-slack-request-timestamp': ts,
    });
    await handler(event as never, {} as never, vi.fn());
    const msg = mockSqsSend.mock.calls[0]![0] as Record<string, unknown>;
    const payload = JSON.parse(msg['MessageBody'] as string) as Record<string, string>;
    expect(payload['eventType']).toBe('app_mention');
  });

  it('extracts intercom event type from x-intercom-topic header', async () => {
    const body = '{}';
    const event = makeEvent('tenant-et3', 'intercom', body, {
      'x-intercom-topic': 'conversation.user.replied',
      'x-hub-signature': intercomSig(body, TEST_SECRET),
    });
    await handler(event as never, {} as never, vi.fn());
    const msg = mockSqsSend.mock.calls[0]![0] as Record<string, unknown>;
    const payload = JSON.parse(msg['MessageBody'] as string) as Record<string, string>;
    expect(payload['eventType']).toBe('conversation.user.replied');
  });
});
