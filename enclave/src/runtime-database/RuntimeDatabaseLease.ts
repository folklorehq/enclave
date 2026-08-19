import {
  runtimeDatabaseConfigSchema,
  type RuntimeDatabaseConfig,
  type RuntimeDatabaseCredentialReceipt,
} from '@folklore/contracts/enclave-attestation';

interface RuntimeDatabaseResource {
  close(): Promise<void>;
}

interface RuntimeDatabaseLeaseOptions {
  requestRestart(exitCode: number): void;
}

export const RUNTIME_DATABASE_RESTART_EXIT_CODE = 75;

export class RuntimeDatabaseLease<
  TApi extends RuntimeDatabaseResource,
  TDatabase extends RuntimeDatabaseResource,
> {
  #config: string | undefined;
  #receipt: RuntimeDatabaseCredentialReceipt | undefined;
  #api: TApi | undefined;
  #database: TDatabase | undefined;
  #restartRequested = false;

  constructor(private readonly options: RuntimeDatabaseLeaseOptions) {}

  activate(
    config: RuntimeDatabaseConfig,
    receipt: RuntimeDatabaseCredentialReceipt,
    api: TApi,
    database: TDatabase,
  ): void {
    const encoded = this.encode(config);
    if (this.#config !== undefined && this.#config !== encoded) {
      throw new Error('runtime_database_config_changed');
    }
    this.#config = encoded;
    this.#receipt = receipt;
    this.#api = api;
    this.#database = database;
  }

  async reconcile(config: RuntimeDatabaseConfig): Promise<'retained' | 'restart-requested'> {
    if (this.#restartRequested) return 'restart-requested';
    const encoded = this.encode(config);
    if (this.#config === undefined) {
      this.#config = encoded;
      return 'retained';
    }
    if (this.#config === encoded) return 'retained';
    const api = this.#api;
    const database = this.#database;
    this.#config = encoded;
    this.#receipt = undefined;
    this.#api = undefined;
    this.#database = undefined;
    this.#restartRequested = true;
    await Promise.allSettled([api?.close(), database?.close()]);
    this.options.requestRestart(RUNTIME_DATABASE_RESTART_EXIT_CODE);
    return 'restart-requested';
  }

  receipt(): RuntimeDatabaseCredentialReceipt | undefined {
    return this.#receipt;
  }

  api(): TApi | undefined {
    return this.#api;
  }

  private encode(config: RuntimeDatabaseConfig): string {
    return JSON.stringify(runtimeDatabaseConfigSchema.parse(config));
  }
}
