export type TenantEviction = (tenantId: string) => void | Promise<void>;

export interface TenantGenerationQuiescenceDeps {
  readonly fence: (tenantId: string) => Promise<void>;
  readonly holdWork: (tenantId: string) => void;
  readonly evictWork: readonly TenantEviction[];
  readonly evictAlongsideDrain: readonly TenantEviction[];
  readonly evictAfterDrain: TenantEviction;
}

export interface TenantGenerationQuiescence {
  readonly quiesceWork: (tenantId: string) => Promise<void>;
  readonly quiesceRequests: (tenantId: string) => Promise<void>;
}

const GENERATION_QUIESCE_FAILED = 'tenant_generation_quiesce_failed';

/** Quiesces queue work without a request fence, then fences requests and evicts what they hold or rebuild. */
export function createTenantGenerationQuiescence(
  deps: TenantGenerationQuiescenceDeps,
): TenantGenerationQuiescence {
  return {
    quiesceWork: (tenantId) => {
      deps.holdWork(tenantId);
      return settleAll(startAll(deps.evictWork, tenantId));
    },
    quiesceRequests: (tenantId) => {
      const requestDrain = deps.fence(tenantId);
      return settleAll([
        requestDrain,
        requestDrain.then(() => deps.evictAfterDrain(tenantId)),
        ...startAll(deps.evictAlongsideDrain, tenantId),
      ]);
    },
  };
}

function startAll(evictions: readonly TenantEviction[], tenantId: string): Promise<void>[] {
  return evictions.map((evict) => Promise.resolve().then(() => evict(tenantId)));
}

async function settleAll(work: readonly Promise<unknown>[]): Promise<void> {
  const results = await Promise.allSettled(work);
  if (results.some((result) => result.status === 'rejected')) {
    throw new Error(GENERATION_QUIESCE_FAILED);
  }
}
