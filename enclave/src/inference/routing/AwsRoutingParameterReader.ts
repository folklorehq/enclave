import { GetParameterCommand, type SSMClient } from '@aws-sdk/client-ssm';

const PARAMETER_NOT_FOUND = 'ParameterNotFound';

export interface RoutingParameterValue {
  readonly arn: string | undefined;
  readonly value: string | undefined;
}

export interface RoutingParameterReader {
  read(): Promise<RoutingParameterValue | 'absent'>;
}

export class AwsRoutingParameterReader implements RoutingParameterReader {
  constructor(
    private readonly ssm: Pick<SSMClient, 'send'>,
    private readonly parameterArn: string,
  ) {}

  async read(): Promise<RoutingParameterValue | 'absent'> {
    try {
      const response = await this.ssm.send(
        new GetParameterCommand({ Name: this.parameterArn, WithDecryption: false }),
      );
      return { arn: response.Parameter?.ARN, value: response.Parameter?.Value };
    } catch (error) {
      if (error instanceof Error && error.name === PARAMETER_NOT_FOUND) return 'absent';
      throw error;
    }
  }
}
