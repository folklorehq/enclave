import { request } from 'node:http';

const HOST = process.env['OLLAMA_HOST'] ?? '';

function httpPost(host: string, path: string, body: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const [hostname, portStr] = host.split(':');
    const req = request(
      {
        hostname: hostname ?? 'localhost',
        port: portStr ? Number(portStr) : 11434,
        path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch (e) {
            reject(e);
          }
        });
      },
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

export async function embedText(text: string): Promise<number[]> {
  if (!HOST) return new Array(768).fill(0) as number[];
  const res = (await httpPost(HOST, '/api/embeddings', {
    model: 'nomic-embed-text',
    prompt: text,
  })) as { embedding: number[] };
  return res.embedding;
}
