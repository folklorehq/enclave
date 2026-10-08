import { GetObjectCommand, NoSuchKey, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';

// A v1 blob could have been sealed outside an attested enclave, so only the minted v2 blob is read.
export function sealedBlobKey(tenantId: string): string {
  return `sealed-keys/${tenantId}/master.v2.blob`;
}

export async function readSealedBlob(
  s3: S3Client,
  bucket: string,
  tenantId: string,
): Promise<Buffer | null> {
  try {
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: bucket, Key: sealedBlobKey(tenantId) }),
    );
    if (!obj.Body) throw new Error('sealed blob unavailable');
    return Buffer.from(await obj.Body.transformToByteArray());
  } catch (err) {
    if (!(err instanceof NoSuchKey)) throw err;
    return null;
  }
}

export async function writeSealedBlob(
  s3: S3Client,
  bucket: string,
  tenantId: string,
  body: Buffer,
): Promise<void> {
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: sealedBlobKey(tenantId), Body: body }));
}
