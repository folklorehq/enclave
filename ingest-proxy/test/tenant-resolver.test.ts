import { createHmac } from 'crypto';
import { describe, expect, it } from 'vitest';

// Import extractors and types from the source module
import { EXTRACTORS, type ExtractorFn, clearRoutingCache } from '../src/tenant-resolver.js';

// Helper to get a private extractor by key from the EXTRACTORS map
function getExtractor(source: string): ExtractorFn {
  const fn = EXTRACTORS[source];
  if (!fn) throw new Error(`No extractor for source: ${source}`);
  return fn;
}

describe('githubExtractor', () => {
  const extractor = getExtractor('github');

  it('returns the installation id from a valid payload', () => {
    const body = { installation: { id: 12345678 } };
    expect(extractor(body, {})).toBe('12345678');
  });

  it('returns null for empty payload', () => {
    expect(extractor({}, {})).toBeNull();
  });

  it('returns null when installation is missing', () => {
    expect(extractor({ action: 'opened' }, {})).toBeNull();
  });

  it('returns null for null body', () => {
    expect(extractor(null, {})).toBeNull();
  });
});

describe('slackExtractor', () => {
  const extractor = getExtractor('slack');

  it('returns team_id from a valid event_callback payload', () => {
    const body = { type: 'event_callback', team_id: 'T12345', event: { type: 'message' } };
    expect(extractor(body, {})).toBe('T12345');
  });

  it('returns null for url_verification payload', () => {
    const body = { type: 'url_verification', challenge: 'abc123' };
    expect(extractor(body, {})).toBeNull();
  });

  it('returns null when team_id is missing', () => {
    const body = { type: 'event_callback', event: { type: 'message' } };
    expect(extractor(body, {})).toBeNull();
  });

  it('returns null for null body', () => {
    expect(extractor(null, {})).toBeNull();
  });
});

describe('linearExtractor', () => {
  const extractor = getExtractor('linear');

  it('returns the organizationId from a valid payload', () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    const body = { organizationId: uuid, type: 'Issue', action: 'create' };
    expect(extractor(body, {})).toBe(uuid);
  });

  it('returns null when organizationId is missing', () => {
    expect(extractor({ type: 'Issue' }, {})).toBeNull();
  });

  it('returns null for null body', () => {
    expect(extractor(null, {})).toBeNull();
  });
});

describe('notionExtractor', () => {
  const extractor = getExtractor('notion');

  it('returns the workspace_id from a valid payload', () => {
    const uuid = 'abc123-456-def';
    const body = { workspace_id: uuid, type: 'page.created' };
    expect(extractor(body, {})).toBe(uuid);
  });

  it('returns null when workspace_id is missing', () => {
    expect(extractor({ type: 'page.created' }, {})).toBeNull();
  });

  it('returns null for null body', () => {
    expect(extractor(null, {})).toBeNull();
  });
});

describe('zoomExtractor', () => {
  const extractor = getExtractor('zoom');

  it('returns the account_id from a meeting.started event payload', () => {
    const body = {
      event: 'meeting.started',
      payload: { account_id: 'acc123', object: { id: 42 } },
    };
    expect(extractor(body, {})).toBe('acc123');
  });

  it('returns null for endpoint.url_validation event', () => {
    const body = {
      event: 'endpoint.url_validation',
      payload: { plainToken: 'some-token' },
    };
    expect(extractor(body, {})).toBeNull();
  });

  it('returns null when payload is missing', () => {
    const body = { event: 'meeting.started' };
    expect(extractor(body, {})).toBeNull();
  });

  it('returns null when account_id is missing from payload', () => {
    const body = { event: 'meeting.started', payload: { object: { id: 42 } } };
    expect(extractor(body, {})).toBeNull();
  });

  it('returns null for null body', () => {
    expect(extractor(null, {})).toBeNull();
  });
});

describe('intercomExtractor', () => {
  const extractor = getExtractor('intercom');

  it('returns the app_id from a valid payload', () => {
    const body = { app_id: 'app123', type: 'notification_event' };
    expect(extractor(body, {})).toBe('app123');
  });

  it('returns null when app_id is missing', () => {
    expect(extractor({ type: 'notification_event' }, {})).toBeNull();
  });

  it('returns null for null body', () => {
    expect(extractor(null, {})).toBeNull();
  });
});

describe('jwtIssExtractor (jira)', () => {
  const extractor = getExtractor('jira');

  function makeJwt(payload: Record<string, unknown>, secret = 'test-secret'): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }), 'utf8').toString(
      'base64url',
    );
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig = createHmac('sha256', secret).update(`${header}.${payloadB64}`).digest('base64url');
    return `${header}.${payloadB64}.${sig}`;
  }

  it('returns the iss claim from a valid JWT', () => {
    const jwt = makeJwt({ iss: 'client-abc', exp: 9999999999 });
    expect(extractor(null, { authorization: `JWT ${jwt}` })).toBe('client-abc');
  });

  it('returns null when no Authorization header is present', () => {
    expect(extractor(null, {})).toBeNull();
  });

  it('returns null when Authorization header is not a JWT', () => {
    expect(extractor(null, { authorization: 'Bearer token' })).toBeNull();
  });

  it('returns null when the JWT has no iss claim', () => {
    const jwt = makeJwt({ exp: 9999999999 });
    expect(extractor(null, { authorization: `JWT ${jwt}` })).toBeNull();
  });

  it('returns null when the JWT is malformed', () => {
    expect(extractor(null, { authorization: 'JWT not-a-valid-jwt' })).toBeNull();
  });
});

describe('jwtIssExtractor (confluence)', () => {
  const extractor = getExtractor('confluence');

  function makeJwt(payload: Record<string, unknown>, secret = 'test-secret'): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }), 'utf8').toString(
      'base64url',
    );
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig = createHmac('sha256', secret).update(`${header}.${payloadB64}`).digest('base64url');
    return `${header}.${payloadB64}.${sig}`;
  }

  it('returns the iss claim from a valid JWT (confluence)', () => {
    const jwt = makeJwt({ iss: 'confluence-tenant-xyz', exp: 9999999999 });
    expect(extractor(null, { authorization: `JWT ${jwt}` })).toBe('confluence-tenant-xyz');
  });
});

describe('clearRoutingCache', () => {
  it('is a function that clears the internal cache', () => {
    // Should not throw
    expect(() => clearRoutingCache()).not.toThrow();
  });
});
