import { DynamoDBClient, UpdateItemCommand } from '@aws-sdk/client-dynamodb';

const dynamo = new DynamoDBClient({});
const TABLE = process.env['RATE_LIMIT_TABLE'];
// Default: 120 requests per minute per (tenant, source).
const LIMIT = Number(process.env['RATE_LIMIT_RPM'] ?? 120);
const WINDOW_S = 60;

export async function checkRateLimit(tenantId: string, source: string): Promise<boolean> {
  if (!TABLE) return true;

  const window = Math.floor(Date.now() / (WINDOW_S * 1000));
  const pk = `${tenantId}/${source}`;
  const sk = String(window);
  const ttl = String(window * WINDOW_S + WINDOW_S * 2); // expire 2 windows after creation

  const result = await dynamo.send(
    new UpdateItemCommand({
      TableName: TABLE,
      Key: { pk: { S: pk }, sk: { S: sk } },
      UpdateExpression: 'ADD #cnt :one SET #ttl = if_not_exists(#ttl, :ttl)',
      ExpressionAttributeNames: { '#cnt': 'count', '#ttl': 'ttl' },
      ExpressionAttributeValues: { ':one': { N: '1' }, ':ttl': { N: ttl } },
      ReturnValues: 'UPDATED_NEW',
    }),
  );

  const count = Number(result.Attributes?.['count']?.N ?? 1);
  return count <= LIMIT;
}
