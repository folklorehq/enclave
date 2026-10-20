import { INFERENCE_ROUTING_TABLE_PARAMETER } from '@folklore/contracts';

export function routingParameterArn(scope: {
  readonly awsAccountId: string;
  readonly awsRegion: string;
}): string {
  return `arn:aws:ssm:${scope.awsRegion}:${scope.awsAccountId}:parameter${INFERENCE_ROUTING_TABLE_PARAMETER}`;
}
