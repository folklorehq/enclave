import { GetSecretValueCommand, type SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { GetParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';
import type {
  SecretsManagerSecretValuePort,
  SsmParameterValuePort,
} from './BootManifestSecretLoader.js';

export class AwsBootManifestSecretsManager implements SecretsManagerSecretValuePort {
  constructor(private readonly client: SecretsManagerClient) {}

  async getSecretValue(input: { secretId: string; versionId: string }) {
    const response = await this.client.send(
      new GetSecretValueCommand({ SecretId: input.secretId, VersionId: input.versionId }),
    );
    return {
      arn: response.ARN,
      versionId: response.VersionId,
      secretString: response.SecretString,
      secretBinary: response.SecretBinary,
    };
  }
}

export class AwsBootManifestSsmParameters implements SsmParameterValuePort {
  constructor(private readonly client: SSMClient) {}

  async getParameter(input: { name: string; version: number; withDecryption?: boolean }) {
    const response = await this.client.send(
      new GetParameterCommand({
        Name: `${input.name}:${input.version}`,
        WithDecryption: input.withDecryption ?? true,
      }),
    );
    return {
      name: response.Parameter?.Name,
      version: response.Parameter?.Version,
      value: response.Parameter?.Value,
    };
  }
}
