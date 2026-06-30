import { createServer } from 'node:http';

export function startHealthServer(port = 3000): void {
  createServer((req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    } else {
      res.writeHead(404).end();
    }
  }).listen(port, '127.0.0.1');
  console.log('health server listening', { port });
}
