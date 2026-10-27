import type { SsmParameterValuePort } from '../attestation/BootManifestSecretLoader.js';
import { readFailureCode } from '../attestation/read-failure-code.js';

export interface SsmSecretLoadErrors {
  readonly read: string;
  readonly accessDenied: string;
  readonly missing: string;
}

export class SsmSecretLoader {
  constructor(
    private readonly ssm: SsmParameterValuePort,
    private readonly errors: SsmSecretLoadErrors,
  ) {}

  async load(path: string): Promise<string> {
    const value = await this.read(path);
    if (!value) throw new Error(this.errors.missing);
    return value;
  }

  private async read(path: string): Promise<string | undefined> {
    try {
      return (await this.ssm.getParameter({ name: path, withDecryption: true })).value;
    } catch (error) {
      throw new Error(readFailureCode(error, this.errors.read, this.errors.accessDenied));
    }
  }
}
