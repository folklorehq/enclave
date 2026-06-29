import { request } from 'node:http';

const PORT = process.env['TINFOIL_PORT'];

function httpPost(port: string, path: string, body: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = request(
      {
        hostname: 'localhost',
        port: Number(port),
        path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString()));
          } catch (e) {
            reject(e);
          }
        });
      },
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

export async function embedText(text: string): Promise<number[]> {
  if (!PORT) return new Array(768).fill(0) as number[];
  const res = (await httpPost(PORT, '/embed', { text })) as { embedding: number[] };
  return res.embedding;
}

export async function synthesize(context: unknown): Promise<string> {
  if (!PORT) return '';
  const res = (await httpPost(PORT, '/synthesize', { context })) as { text: string };
  return res.text;
}
