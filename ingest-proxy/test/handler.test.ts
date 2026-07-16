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

function jiraSig(body: string, secret: string) {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

function notionSig(body: string, secret: string) {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

function meetingSig(body: string, secret: string) {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

const RECALL_SECRET = 'whsec_' + Buffer.from('recall-signing-secret-bytes').toString('base64');

function svixSig(id: string, ts: string, body: string, secret: string) {
  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
  return 'v1,' + createHmac('sha256', key).update(`${id}.${ts}.${body}`, 'utf8').digest('base64');
}

function zoomSig(body: string, secret: string, ts: string) {
  return 'v0=' + createHmac('sha256', secret).update(`v0:${ts}:${body}`).digest('hex');
}

function b64url(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64url');
}

function confluenceJwt(
  secret: string,
  opts: { alg?: string; expOffsetS?: number; sign?: string; omitExp?: boolean; exp?: unknown } = {},
): string {
  const nowS = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: opts.alg ?? 'HS256', typ: 'JWT' }));
  const claims: Record<string, unknown> = { iss: 'client-key', iat: nowS };
  if (!opts.omitExp) claims['exp'] = 'exp' in opts ? opts.exp : nowS + (opts.expOffsetS ?? 300);
  const payload = b64url(JSON.stringify(claims));
  const sig = createHmac('sha256', opts.sign ?? secret)
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${sig}`;
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
  const nowS = () => Math.floor(Date.now() / 1000);
  const freshTs = String(nowS());
  const staleTs = String(nowS() - 400);

  function mockSlackSecret() {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/slack'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });
  }

  async function run(headers: Record<string, string>) {
    return handler(makeEvent(tid, 'slack', body, headers) as never, {} as never, vi.fn());
  }

  it('returns 200 when v0 signature is valid with fresh timestamp', async () => {
    mockSlackSecret();
    const result = await run({
      'x-slack-signature': slackSig(body, TEST_SECRET, freshTs),
      'x-slack-request-timestamp': freshTs,
    });
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('returns 401 on replay attack (timestamp > 5 min old)', async () => {
    mockSlackSecret();
    const result = await run({
      'x-slack-signature': slackSig(body, TEST_SECRET, staleTs),
      'x-slack-request-timestamp': staleTs,
    });
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 when the timestamp is far in the future (abs replay window)', async () => {
    mockSlackSecret();
    const futureTs = String(nowS() + 400);
    const result = await run({
      'x-slack-signature': slackSig(body, TEST_SECRET, futureTs),
      'x-slack-request-timestamp': futureTs,
    });
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('accepts a signature just inside the 5-minute window', async () => {
    mockSlackSecret();
    const edgeTs = String(nowS() - 299);
    const result = await run({
      'x-slack-signature': slackSig(body, TEST_SECRET, edgeTs),
      'x-slack-request-timestamp': edgeTs,
    });
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('returns 401 when the body is tampered after signing', async () => {
    mockSlackSecret();
    const result = await run({
      'x-slack-signature': slackSig('{"type":"other"}', TEST_SECRET, freshTs),
      'x-slack-request-timestamp': freshTs,
    });
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 when signed with the wrong secret', async () => {
    mockSlackSecret();
    const result = await run({
      'x-slack-signature': slackSig(body, 'not-the-secret', freshTs),
      'x-slack-request-timestamp': freshTs,
    });
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 when the timestamp header is missing', async () => {
    mockSlackSecret();
    const result = await run({ 'x-slack-signature': slackSig(body, TEST_SECRET, freshTs) });
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 when the signature lacks the v0= scheme prefix', async () => {
    mockSlackSecret();
    const bare = slackSig(body, TEST_SECRET, freshTs).slice(3);
    const result = await run({
      'x-slack-signature': bare,
      'x-slack-request-timestamp': freshTs,
    });
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

  it('verifies the original `Linear-Signature` casing (case-insensitive lookup)', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/linear'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'linear', body, {
      'Linear-Signature': linearSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('returns 401 when the signature is tampered', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/linear'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'linear', body, {
      'linear-signature': linearSig(body, 'wrong-secret'),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 when the body is tampered after signing', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/linear'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const signed = linearSig(body, TEST_SECRET);
    const tamperedBody = JSON.stringify({ type: 'Issue', action: 'create', injected: true });
    const event = makeEvent(tid, 'linear', tamperedBody, { 'linear-signature': signed });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 (fail closed) when no secret is configured', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });

    const event = makeEvent('tenant-li-open', 'linear', body, {
      'linear-signature': linearSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
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

  it('returns 401 when the sha1 signature is wrong', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/intercom'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'intercom', body, {
      'x-hub-signature': intercomSig(body, 'wrong-secret'),
      'x-intercom-topic': 'conversation.user.created',
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 when the digest is correct but the prefix is not sha1= (a sha256= header is rejected)', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/intercom'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const sha1Hex = createHmac('sha1', TEST_SECRET).update(body).digest('hex');
    const event = makeEvent(tid, 'intercom', body, {
      'x-hub-signature': `sha256=${sha1Hex}`,
      'x-intercom-topic': 'conversation.user.created',
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 when the sha1= prefix is missing (bare hex digest)', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/intercom'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const bareHex = createHmac('sha1', TEST_SECRET).update(body).digest('hex');
    const event = makeEvent(tid, 'intercom', body, {
      'x-hub-signature': bareHex,
      'x-intercom-topic': 'conversation.user.created',
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 (fail closed) when no intercom secret is configured', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });

    const event = makeEvent('tenant-ic-open', 'intercom', body, {
      'x-hub-signature': intercomSig(body, TEST_SECRET),
      'x-intercom-topic': 'conversation.user.created',
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

describe('HMAC signature verification — Jira', () => {
  const tid = 'tenant-ji';
  const body = JSON.stringify({ webhookEvent: 'jira:issue_created', issue: { key: 'PROJ-1' } });

  it('returns 200 when the native X-Hub-Signature sha256 is valid', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/jira')) return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'jira', body, {
      'x-hub-signature': jiraSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('returns 401 when the body is tampered after signing', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/jira')) return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const tampered = JSON.stringify({
      webhookEvent: 'jira:issue_created',
      issue: { key: 'EVIL-9' },
    });
    const event = makeEvent(tid, 'jira', tampered, {
      'x-hub-signature': jiraSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 when signed with the wrong secret', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/jira')) return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'jira', body, {
      'x-hub-signature': jiraSig(body, 'wrong-secret'),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 when the sha256= prefix is absent', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/jira')) return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent(tid, 'jira', body, {
      'x-hub-signature': createHmac('sha256', TEST_SECRET).update(body).digest('hex'),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 (fail closed) when no secret is configured', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });

    const event = makeEvent('tenant-ji-open', 'jira', body, {
      'x-hub-signature': jiraSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('extracts the event type from the body webhookEvent field', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/jira')) return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });

    const event = makeEvent('tenant-ji-et', 'jira', body, {
      'x-hub-signature': jiraSig(body, TEST_SECRET),
    });
    await handler(event as never, {} as never, vi.fn());
    const msg = mockSqsSend.mock.calls[0]![0] as Record<string, unknown>;
    const payload = JSON.parse(msg['MessageBody'] as string) as Record<string, string>;
    expect(payload['eventType']).toBe('jira:issue_created');
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

describe('Notion subscription verification handshake', () => {
  it('ACKs the unsigned verification_token POST with 200 and does not forward to SQS', async () => {
    const body = JSON.stringify({ verification_token: 'secret_tok_abc' });
    const event = makeEvent('tenant-nvh-1', 'notion', body, {});
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('does not short-circuit a signed event that also carries a verification_token field', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });
    const body = JSON.stringify({ type: 'page.created', verification_token: 'x' });
    const event = makeEvent('tenant-nvh-2', 'notion', body, {
      'x-notion-signature': notionSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('forwards a real event once the captured verification_token is the stored secret', async () => {
    const token = 'secret_tok_live';
    const body = JSON.stringify({ type: 'page.created', page: { id: 'p1' } });
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/notion')) return { Parameter: { Value: token } };
      throw new Error('ParameterNotFound');
    });
    const event = makeEvent('tenant-nvh-3', 'notion', body, {
      'x-notion-signature': notionSig(body, token),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
    expect(mockSqsSend).toHaveBeenCalledTimes(1);
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
      'x-meeting-event': 'vtt_upload',
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
      'x-meeting-event': 'vtt_upload',
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
      'x-meeting-event': 'vtt_upload',
      'x-meeting-signature': meetingSig(body, TEST_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

describe('Svix signature verification — Zoom bot (Recall.ai)', () => {
  const tid = 'tenant-zb';
  const body = JSON.stringify({ event: 'transcript.done', data: { bot: { id: 'bot-1' } } });
  const freshTs = String(Math.floor(Date.now() / 1000));
  const staleTs = String(Math.floor(Date.now() / 1000) - 400);

  function withSecret() {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/zoom_bot'))
        return { Parameter: { Value: RECALL_SECRET } };
      throw new Error('ParameterNotFound');
    });
  }

  it('returns 200 for a valid base64 v1 signature with a fresh timestamp', async () => {
    withSecret();
    const event = makeEvent(tid, 'zoom_bot', body, {
      'webhook-id': 'msg_abc',
      'webhook-timestamp': freshTs,
      'webhook-signature': svixSig('msg_abc', freshTs, body, RECALL_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('accepts the svix-* header aliases', async () => {
    withSecret();
    const event = makeEvent(tid, 'zoom_bot', body, {
      'svix-id': 'msg_abc',
      'svix-timestamp': freshTs,
      'svix-signature': svixSig('msg_abc', freshTs, body, RECALL_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('returns 401 when the signature is wrong', async () => {
    withSecret();
    const event = makeEvent(tid, 'zoom_bot', body, {
      'webhook-id': 'msg_abc',
      'webhook-timestamp': freshTs,
      'webhook-signature': svixSig(
        'msg_abc',
        freshTs,
        body,
        'whsec_' + Buffer.from('other').toString('base64'),
      ),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 on a stale timestamp (replay guard)', async () => {
    withSecret();
    const event = makeEvent(tid, 'zoom_bot', body, {
      'webhook-id': 'msg_abc',
      'webhook-timestamp': staleTs,
      'webhook-signature': svixSig('msg_abc', staleTs, body, RECALL_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 on a non-numeric timestamp (NaN never slips past the replay window)', async () => {
    withSecret();
    const event = makeEvent(tid, 'zoom_bot', body, {
      'webhook-id': 'msg_abc',
      'webhook-timestamp': 'not-a-number',
      'webhook-signature': svixSig('msg_abc', 'not-a-number', body, RECALL_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('extracts the event type from the JSON body and dedups on the webhook id', async () => {
    withSecret();
    mockSqsSend.mockClear();
    const event = makeEvent(tid, 'zoom_bot', body, {
      'webhook-id': 'msg_dedup',
      'webhook-timestamp': freshTs,
      'webhook-signature': svixSig('msg_dedup', freshTs, body, RECALL_SECRET),
    });
    await handler(event as never, {} as never, vi.fn());
    const msg = mockSqsSend.mock.calls[0]![0] as Record<string, unknown>;
    const payload = JSON.parse(msg['MessageBody'] as string) as Record<string, string>;
    expect(payload['eventType']).toBe('transcript.done');
    expect(payload['source']).toBe('zoom_bot');
  });

  it('returns 401 (fail closed) when no secret is configured', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });
    const event = makeEvent('tenant-zb-open', 'zoom_bot', body, {
      'webhook-id': 'msg_abc',
      'webhook-timestamp': freshTs,
      'webhook-signature': svixSig('msg_abc', freshTs, body, RECALL_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

describe('Zoom — signature verification + url_validation', () => {
  const tid = 'tenant-zm';
  const ts = String(Math.floor(Date.now() / 1000));
  const body = JSON.stringify({
    event: 'recording.transcript_completed',
    payload: { object: { uuid: 'abc==' } },
  });

  function withSecret() {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/zoom')) return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });
  }

  it('returns 200 for a valid v0 signature', async () => {
    withSecret();
    const event = makeEvent(tid, 'zoom', body, {
      'x-zm-signature': zoomSig(body, TEST_SECRET, ts),
      'x-zm-request-timestamp': ts,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
    expect(mockSqsSend).toHaveBeenCalledTimes(1);
  });

  it('returns 401 for a tampered signature', async () => {
    withSecret();
    const event = makeEvent(tid, 'zoom', body, {
      'x-zm-signature': zoomSig(body, 'wrong-secret', ts),
      'x-zm-request-timestamp': ts,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 on replay attack (timestamp > 5 min old)', async () => {
    withSecret();
    const staleTs = String(Math.floor(Date.now() / 1000) - 400);
    const event = makeEvent(tid, 'zoom', body, {
      'x-zm-signature': zoomSig(body, TEST_SECRET, staleTs),
      'x-zm-request-timestamp': staleTs,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 when the timestamp is non-numeric (fail closed, no NaN bypass)', async () => {
    withSecret();
    const event = makeEvent(tid, 'zoom', body, {
      'x-zm-signature': zoomSig(body, TEST_SECRET, 'not-a-number'),
      'x-zm-request-timestamp': 'not-a-number',
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('answers endpoint.url_validation only when the request carries a valid signature', async () => {
    withSecret();
    const plainToken = 'plain-token-xyz';
    const challengeBody = JSON.stringify({
      event: 'endpoint.url_validation',
      payload: { plainToken },
    });
    const event = makeEvent(tid, 'zoom', challengeBody, {
      'x-zm-signature': zoomSig(challengeBody, TEST_SECRET, ts),
      'x-zm-request-timestamp': ts,
    });
    const result = (await handler(event as never, {} as never, vi.fn())) as {
      statusCode: number;
      body: string;
    };
    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body) as { plainToken: string; encryptedToken: string };
    expect(parsed.plainToken).toBe(plainToken);
    expect(parsed.encryptedToken).toBe(
      createHmac('sha256', TEST_SECRET).update(plainToken).digest('hex'),
    );
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  // The oracle: HMAC(secret, plainToken) with attacker-chosen plainToken equals a message
  // signature HMAC(secret, `v0:{ts}:{forgedBody}`) over the same secret. An attacker who does NOT
  // hold the secret can only obtain that HMAC if the CRC echo answers an unsigned request — so
  // prove the unsigned url_validation is rejected and never leaks the HMAC. Without the echo, the
  // attacker cannot produce a valid x-zm-signature for their forged body.
  it('does not act as a signature-forgery oracle for an unauthenticated caller', async () => {
    withSecret();
    const forgedBody = JSON.stringify({
      event: 'recording.transcript_completed',
      payload: { object: { uuid: 'attacker-forged' } },
    });
    const oracleInput = `v0:${ts}:${forgedBody}`;
    const forgedSig = createHmac('sha256', TEST_SECRET).update(oracleInput).digest('hex');

    const challengeBody = JSON.stringify({
      event: 'endpoint.url_validation',
      payload: { plainToken: oracleInput },
    });
    const oracleQuery = makeEvent(tid, 'zoom', challengeBody, {});
    const oracleResult = (await handler(oracleQuery as never, {} as never, vi.fn())) as {
      statusCode: number;
      body?: string;
    };

    // The echo is gated behind a valid signature the attacker can't produce: 401, no HMAC leaked.
    expect(oracleResult.statusCode).toBe(401);
    expect(oracleResult.body ?? '').not.toContain(forgedSig);
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

// Recall bots and native Zoom both post to the `zoom` source path, but Recall signs with the SINGLE
// global workspace secret (Svix), never the per-tenant Zoom Secret Token (design §4/§8).
describe('Recall inbound on the `zoom` path — global workspace secret (Svix)', () => {
  const tid = 'tenant-recall';
  const body = JSON.stringify({ event: 'transcript.done', data: { bot: { id: 'bot-9' } } });
  const freshTs = String(Math.floor(Date.now() / 1000));
  const RECALL_GLOBAL = 'whsec_' + Buffer.from('recall-workspace-secret').toString('base64');
  const PER_TENANT_ZOOM = 'per-tenant-zoom-secret';

  function withSecrets() {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name === '/folklore/recall-api/webhook-verification-secret')
        return { Parameter: { Value: RECALL_GLOBAL } };
      if (cmd.Name?.includes('/webhook-secrets/zoom'))
        return { Parameter: { Value: PER_TENANT_ZOOM } };
      throw new Error('ParameterNotFound');
    });
  }

  it('verifies a Recall webhook against the GLOBAL secret, not the per-tenant path', async () => {
    withSecrets();
    const event = makeEvent(tid, 'zoom', body, {
      'webhook-id': 'msg_r1',
      'webhook-timestamp': freshTs,
      'webhook-signature': svixSig('msg_r1', freshTs, body, RECALL_GLOBAL),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
    expect(mockSqsSend).toHaveBeenCalledTimes(1);
  });

  it('fails closed on a Recall webhook signed with the wrong (per-tenant) secret', async () => {
    withSecrets();
    const event = makeEvent(tid, 'zoom', body, {
      'webhook-id': 'msg_r1',
      'webhook-timestamp': freshTs,
      'webhook-signature': svixSig('msg_r1', freshTs, body, RECALL_SECRET),
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('still verifies a native Zoom webhook against the per-tenant Zoom Secret Token', async () => {
    withSecrets();
    const zoomBody = JSON.stringify({
      event: 'recording.transcript_completed',
      payload: { object: { uuid: 'zoom-uuid-1' } },
    });
    const event = makeEvent(tid, 'zoom', zoomBody, {
      'x-zm-signature': zoomSig(zoomBody, PER_TENANT_ZOOM, freshTs),
      'x-zm-request-timestamp': freshTs,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
    expect(mockSqsSend).toHaveBeenCalledTimes(1);
  });
});

// The global Recall secret has a tenant-independent cache key, so a sibling test that provisions it
// poisons the shared in-process cache; a fresh module import gives this fail-closed check a clean cache.
describe('Recall inbound — absent GLOBAL secret (fresh module cache)', () => {
  it('returns 401 and never enqueues to SQS when the global secret is unprovisioned', async () => {
    vi.resetModules();
    mockSqsSend.mockClear();
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });
    const { handler: freshHandler } = await import('../src/handler.js');
    const ts = String(Math.floor(Date.now() / 1000));
    const body = JSON.stringify({ event: 'transcript.done', data: { bot: { id: 'bot-open' } } });
    const secret = 'whsec_' + Buffer.from('recall-workspace-secret').toString('base64');
    const event = makeEvent('tenant-recall-open', 'zoom', body, {
      'webhook-id': 'msg_open',
      'webhook-timestamp': ts,
      'webhook-signature': svixSig('msg_open', ts, body, secret),
    });
    const result = await freshHandler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

describe('JWT verification — Confluence (Atlassian Connect)', () => {
  const tid = 'tenant-cf';
  const body = JSON.stringify({ webhookEvent: 'page_created', page: { id: 'p1' } });

  function mockSecret() {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/confluence'))
        return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });
  }

  it('returns 200 for a valid HS256 JWT in the Authorization header', async () => {
    mockSecret();
    const event = makeEvent(tid, 'confluence', body, {
      authorization: `JWT ${confluenceJwt(TEST_SECRET)}`,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
  });

  it('returns 401 when signed with the wrong secret', async () => {
    mockSecret();
    const event = makeEvent(tid, 'confluence', body, {
      authorization: `JWT ${confluenceJwt(TEST_SECRET, { sign: 'wrong-secret' })}`,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 (rejects alg:none) even with a matching signature slot', async () => {
    mockSecret();
    const event = makeEvent(tid, 'confluence', body, {
      authorization: `JWT ${confluenceJwt(TEST_SECRET, { alg: 'none' })}`,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 for an expired JWT', async () => {
    mockSecret();
    const event = makeEvent(tid, 'confluence', body, {
      authorization: `JWT ${confluenceJwt(TEST_SECRET, { expOffsetS: -3600 })}`,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
  });

  it('returns 401 when exp is omitted (fails closed, not open-ended)', async () => {
    mockSecret();
    const event = makeEvent(tid, 'confluence', body, {
      authorization: `JWT ${confluenceJwt(TEST_SECRET, { omitExp: true })}`,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 when exp is non-numeric', async () => {
    mockSecret();
    const event = makeEvent(tid, 'confluence', body, {
      authorization: `JWT ${confluenceJwt(TEST_SECRET, { exp: 'never' })}`,
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 when the Authorization header is missing', async () => {
    mockSecret();
    const event = makeEvent(tid, 'confluence', body, {});
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

describe('deduplication id determinism', () => {
  beforeEach(() => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/')) return { Parameter: { Value: TEST_SECRET } };
      throw new Error('ParameterNotFound');
    });
  });

  async function dedupIdFor(
    tenantId: string,
    source: string,
    body: string,
    headers: Record<string, string>,
  ): Promise<string> {
    mockSqsSend.mockClear();
    await handler(makeEvent(tenantId, source, body, headers) as never, {} as never, vi.fn());
    const msg = mockSqsSend.mock.calls[0]![0] as Record<string, unknown>;
    return msg['MessageDeduplicationId'] as string;
  }

  it('is a stable sha256 hex, not the random nonce', async () => {
    const body = JSON.stringify({ action: 'opened' });
    const headers = {
      'x-github-event': 'pull_request',
      'x-github-delivery': 'delivery-abc',
      'x-hub-signature-256': githubSig(body, TEST_SECRET),
    };
    const id = await dedupIdFor('tenant-d', 'github', body, headers);
    expect(id).toMatch(/^[0-9a-f]{64}$/);

    const msg = mockSqsSend.mock.calls[0]![0] as Record<string, unknown>;
    const payload = JSON.parse(msg['MessageBody'] as string) as Record<string, string>;
    expect(id).not.toBe(payload['nonce']);
  });

  it('matches for identical redeliveries even though the ciphertext differs', async () => {
    const body = JSON.stringify({ action: 'opened', number: 7 });
    const headers = {
      'x-github-event': 'pull_request',
      'x-github-delivery': 'delivery-xyz',
      'x-hub-signature-256': githubSig(body, TEST_SECRET),
    };
    const first = await dedupIdFor('tenant-d', 'github', body, headers);
    const firstCipher = JSON.parse(
      (mockSqsSend.mock.calls[0]![0] as Record<string, unknown>)['MessageBody'] as string,
    )['ciphertext'] as string;
    const second = await dedupIdFor('tenant-d', 'github', body, headers);
    const secondCipher = JSON.parse(
      (mockSqsSend.mock.calls[0]![0] as Record<string, unknown>)['MessageBody'] as string,
    )['ciphertext'] as string;

    expect(second).toBe(first);
    expect(secondCipher).not.toBe(firstCipher);
  });

  it('prefers the provider delivery id: same delivery id dedups across differing bodies', async () => {
    const bodyA = JSON.stringify({ action: 'opened' });
    const bodyB = JSON.stringify({ action: 'opened', extra: 'retry-jitter' });
    const headers = (body: string) => ({
      'x-github-event': 'pull_request',
      'x-github-delivery': 'delivery-fixed',
      'x-hub-signature-256': githubSig(body, TEST_SECRET),
    });
    const idA = await dedupIdFor('tenant-d', 'github', bodyA, headers(bodyA));
    const idB = await dedupIdFor('tenant-d', 'github', bodyB, headers(bodyB));
    expect(idB).toBe(idA);
  });

  it('differs across tenants for the same delivery', async () => {
    const body = JSON.stringify({ action: 'opened' });
    const headers = {
      'x-github-event': 'pull_request',
      'x-github-delivery': 'delivery-shared',
      'x-hub-signature-256': githubSig(body, TEST_SECRET),
    };
    const idT1 = await dedupIdFor('tenant-one', 'github', body, headers);
    const idT2 = await dedupIdFor('tenant-two', 'github', body, headers);
    expect(idT2).not.toBe(idT1);
  });

  it('differs across sources for the same tenant and body', async () => {
    const body = JSON.stringify({ type: 'page.created' });
    const idNotion = await dedupIdFor('tenant-src', 'notion', body, {
      'x-notion-signature': notionSig(body, TEST_SECRET),
    });
    const idMeeting = await dedupIdFor('tenant-src', 'meeting', body, {
      'x-meeting-event': 'vtt_upload',
      'x-meeting-signature': meetingSig(body, TEST_SECRET),
    });
    expect(idMeeting).not.toBe(idNotion);
  });

  it('falls back to the body when no provider delivery id: same body dedups, different body differs', async () => {
    const bodyA = JSON.stringify({ type: 'page.created', page: { id: 'p1' } });
    const bodyB = JSON.stringify({ type: 'page.created', page: { id: 'p2' } });
    const first = await dedupIdFor('tenant-nb', 'notion', bodyA, {
      'x-notion-signature': notionSig(bodyA, TEST_SECRET),
    });
    const repeat = await dedupIdFor('tenant-nb', 'notion', bodyA, {
      'x-notion-signature': notionSig(bodyA, TEST_SECRET),
    });
    const other = await dedupIdFor('tenant-nb', 'notion', bodyB, {
      'x-notion-signature': notionSig(bodyB, TEST_SECRET),
    });
    expect(repeat).toBe(first);
    expect(other).not.toBe(first);
  });

  it('uses the slack event_id: same event_id dedups across differing bodies', async () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const bodyA = JSON.stringify({ type: 'message', event_id: 'Ev123', text: 'a' });
    const bodyB = JSON.stringify({ type: 'message', event_id: 'Ev123', text: 'b' });
    const idA = await dedupIdFor('tenant-sl-d', 'slack', bodyA, {
      'x-slack-signature': slackSig(bodyA, TEST_SECRET, ts),
      'x-slack-request-timestamp': ts,
    });
    const idB = await dedupIdFor('tenant-sl-d', 'slack', bodyB, {
      'x-slack-signature': slackSig(bodyB, TEST_SECRET, ts),
      'x-slack-request-timestamp': ts,
    });
    expect(idB).toBe(idA);
  });

  it('uses the intercom id: same id dedups across differing bodies', async () => {
    const bodyA = JSON.stringify({ type: 'notification_event', id: 'notif_1', v: 'a' });
    const bodyB = JSON.stringify({ type: 'notification_event', id: 'notif_1', v: 'b' });
    const headers = { 'x-intercom-topic': 'conversation.user.created' };
    const idA = await dedupIdFor('tenant-ic-d', 'intercom', bodyA, {
      ...headers,
      'x-hub-signature': intercomSig(bodyA, TEST_SECRET),
    });
    const idB = await dedupIdFor('tenant-ic-d', 'intercom', bodyB, {
      ...headers,
      'x-hub-signature': intercomSig(bodyB, TEST_SECRET),
    });
    expect(idB).toBe(idA);
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

describe('channel-token verification — Google Drive', () => {
  const tid = 'tenant-gd';
  const CHANNEL_TOKEN = 'watch-channel-token-xyz';

  function driveSecretMock() {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/google_drive'))
        return { Parameter: { Value: CHANNEL_TOKEN } };
      throw new Error('ParameterNotFound');
    });
  }

  it('returns 200 and enqueues a content-free ping when the channel token matches', async () => {
    driveSecretMock();
    const event = makeEvent(tid, 'google_drive', '', {
      'x-goog-channel-token': CHANNEL_TOKEN,
      'x-goog-channel-id': 'chan-1',
      'x-goog-resource-state': 'update',
      'x-goog-resource-id': 'res-abc',
      'x-goog-message-number': '42',
      'x-goog-resource-uri': 'https://www.googleapis.com/drive/v3/changes',
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
    expect(mockSqsSend).toHaveBeenCalledOnce();

    const msg = mockSqsSend.mock.calls[0]![0] as Record<string, unknown>;
    const payload = JSON.parse(msg['MessageBody'] as string) as Record<string, string>;
    expect(payload['source']).toBe('google_drive');
    expect(payload['eventType']).toBe('update');
    expect(msg['MessageDeduplicationId']).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns 401 when the channel token does not match', async () => {
    driveSecretMock();
    const event = makeEvent(tid, 'google_drive', '', {
      'x-goog-channel-token': 'wrong-token',
      'x-goog-resource-state': 'update',
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 401 when the channel token header is absent', async () => {
    driveSecretMock();
    const event = makeEvent(tid, 'google_drive', '', { 'x-goog-resource-state': 'update' });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('acks the sync handshake with 200 and does not enqueue', async () => {
    driveSecretMock();
    const event = makeEvent(tid, 'google_drive', '', {
      'x-goog-channel-token': CHANNEL_TOKEN,
      'x-goog-resource-state': 'sync',
      'x-goog-channel-id': 'chan-1',
      'x-goog-message-number': '1',
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('fails closed with 401 when no channel token is provisioned', async () => {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      throw Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
    });
    const event = makeEvent('tenant-gd-open', 'google_drive', '', {
      'x-goog-channel-token': CHANNEL_TOKEN,
      'x-goog-resource-state': 'update',
    });
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});

describe('clientState verification — Microsoft 365 (Graph)', () => {
  const tid = 'tenant-m365';
  const CLIENT_STATE = 'graph-client-state-secret';

  function m365SecretMock() {
    mockSsmSend.mockImplementation(async (cmd: { Name?: string }) => {
      if (cmd.Name?.endsWith('/ingest-public-key')) return { Parameter: { Value: testPubHex } };
      if (cmd.Name?.includes('/webhook-secrets/microsoft365'))
        return { Parameter: { Value: CLIENT_STATE } };
      throw new Error('ParameterNotFound');
    });
  }

  function notification(clientState: string) {
    return JSON.stringify({
      value: [
        {
          subscriptionId: 'sub-1',
          clientState,
          changeType: 'updated',
          resource: 'drives/drive-1/root',
        },
      ],
    });
  }

  it('echoes the validationToken as text/plain (subscription handshake) without enqueuing', async () => {
    m365SecretMock();
    const event = {
      pathParameters: { tenant_id: tid, source: 'microsoft365' },
      headers: {},
      queryStringParameters: { validationToken: 'opaque-validation-token' },
      body: '',
    };
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({
      statusCode: 200,
      headers: { 'content-type': 'text/plain' },
      body: 'opaque-validation-token',
    });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('returns 200 and enqueues a content-free ping (no clientState) when it matches', async () => {
    m365SecretMock();
    const event = makeEvent(tid, 'microsoft365', notification(CLIENT_STATE));
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 200 });
    expect(mockSqsSend).toHaveBeenCalledOnce();

    const msg = mockSqsSend.mock.calls[0]![0] as Record<string, unknown>;
    const outer = JSON.parse(msg['MessageBody'] as string) as Record<string, string>;
    expect(outer['source']).toBe('microsoft365');
    expect(outer['eventType']).toBe('updated');
    // The clientState secret must never reach SQS — it's decrypted from the ciphertext payload only.
    expect(JSON.stringify(outer)).not.toContain(CLIENT_STATE);
    expect(msg['MessageDeduplicationId']).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns 401 when a notification clientState does not match', async () => {
    m365SecretMock();
    const event = makeEvent(tid, 'microsoft365', notification('wrong-state'));
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });

  it('fails closed (401) when clientState is absent from the notification', async () => {
    m365SecretMock();
    const event = makeEvent(
      tid,
      'microsoft365',
      JSON.stringify({ value: [{ subscriptionId: 'sub-1', changeType: 'updated' }] }),
    );
    const result = await handler(event as never, {} as never, vi.fn());
    expect(result).toMatchObject({ statusCode: 401 });
    expect(mockSqsSend).not.toHaveBeenCalled();
  });
});
