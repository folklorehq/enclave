export interface KmsKeyScope {
  awsAccountId: string;
  awsRegion: string;
}

const BARE_KMS_KEY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ACCOUNT_ID = /^\d{12}$/;
const REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;
const CHINA_REGION_PREFIX = 'cn-';
const GOVCLOUD_REGION_PREFIX = 'us-gov-';

function partitionOf(region: string): string {
  if (region.startsWith(CHINA_REGION_PREFIX)) return 'aws-cn';
  if (region.startsWith(GOVCLOUD_REGION_PREFIX)) return 'aws-us-gov';
  return 'aws';
}

// KMS answers with the full key ARN even when asked by bare id, and the ESDK only decrypts EDKs whose ARN a keyring names.
export function canonicalKmsKeyArn(keyId: string, scope: KmsKeyScope | undefined): string {
  if (!BARE_KMS_KEY_ID.test(keyId) || !scope) return keyId;
  if (!ACCOUNT_ID.test(scope.awsAccountId) || !REGION.test(scope.awsRegion)) {
    throw new Error('kms_key_scope_invalid');
  }
  return `arn:${partitionOf(scope.awsRegion)}:kms:${scope.awsRegion}:${scope.awsAccountId}:key/${keyId}`;
}
