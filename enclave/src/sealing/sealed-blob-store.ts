import { GetObjectCommand, NoSuchKey, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';

export function sealedBlobKey(tenantId: string): string {
  return `sealed-keys/${tenantId}/master.blob`;
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
    return Buffer.from(await obj.Body!.transformToByteArray());
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
