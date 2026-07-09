import { request } from 'node:http';
import { EMBED_DIM } from './phala.js';

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

const EMBED_MODEL = 'nomic-embed-text';
const GENERATE_MODEL = process.env['OLLAMA_MODEL'] ?? 'llama3.2:3b';

export async function embedText(text: string): Promise<number[]> {
  if (!HOST) return new Array(EMBED_DIM).fill(0) as number[];
  const res = (await httpPost(HOST, '/api/embeddings', {
    model: EMBED_MODEL,
    prompt: text,
  })) as { embedding: number[] };
  return res.embedding;
}

export async function generate(prompt: string): Promise<string> {
  if (!HOST) return '';
  const res = (await httpPost(HOST, '/api/generate', {
    model: GENERATE_MODEL,
    prompt,
    stream: false,
  })) as { response: string };
  return res.response;
}
