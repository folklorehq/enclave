import type { RedisCache } from '@folklore/cache';
import type { Logger } from '@folklore/core';
import { poolAssignmentWakeChannel } from '@folklore/contracts';

export interface AssignmentWakeTarget {
  wake(): void;
}

type WakeRedis = Pick<RedisCache['redis'], 'duplicate'>;
type WakeConnection = ReturnType<WakeRedis['duplicate']>;

const SUBSCRIBE_FAILED_EVENT = 'assignment_wake_subscribe_failed';
const SUBSCRIBE_FAILED_CODE = 'assignment_wake_subscribe_failed';
const CONNECTION_FAILED_EVENT = 'assignment_wake_connection_failed';
const CONNECTION_FAILED_CODE = 'assignment_wake_connection_failed';
// The duplicate must never queue or retry a command forever: a stuck subscribe would otherwise outlive the 30 s backstop.
const FAIL_FAST_OPTIONS = { maxRetriesPerRequest: 1, enableOfflineQueue: false } as const;

/** Turns a payload-free pub/sub hint into a refresh request; the signed manifest is still read and verified on every refresh. */
export class AssignmentWakeSubscriber {
  private connection: WakeConnection | undefined;
  private connectionFailureLogged = false;

  constructor(
    private readonly redis: WakeRedis,
    private readonly poolId: string,
    private readonly target: AssignmentWakeTarget,
    private readonly logger: Logger,
  ) {}

  start(): void {
    if (this.connection) return;
    const connection = this.redis.duplicate(FAIL_FAST_OPTIONS);
    this.connection = connection;
    connection.on('error', () => this.logConnectionFailure());
    connection.on('message', (received: string) => {
      if (received === poolAssignmentWakeChannel(this.poolId)) this.target.wake();
    });
    connection.on('ready', () => {
      this.connectionFailureLogged = false;
      this.target.wake();
      void this.subscribe(connection);
    });
  }

  async close(): Promise<void> {
    const connection = this.connection;
    this.connection = undefined;
    if (!connection) return;
    await connection.unsubscribe(poolAssignmentWakeChannel(this.poolId)).catch(() => undefined);
    await connection.quit().catch(() => undefined);
  }

  private async subscribe(connection: WakeConnection): Promise<void> {
    try {
      await connection.subscribe(poolAssignmentWakeChannel(this.poolId));
    } catch {
      this.logger.warn(SUBSCRIBE_FAILED_EVENT, { errorCode: SUBSCRIBE_FAILED_CODE });
    }
  }

  private logConnectionFailure(): void {
    if (this.connectionFailureLogged) return;
    this.connectionFailureLogged = true;
    this.logger.warn(CONNECTION_FAILED_EVENT, { errorCode: CONNECTION_FAILED_CODE });
  }
}
