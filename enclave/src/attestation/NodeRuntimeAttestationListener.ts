import { once } from 'node:events';
import { Server } from 'node:http';
import { serve } from '@hono/node-server';
import type {
  RuntimeAttestationFetchHandler,
  RuntimeAttestationListener,
} from './RuntimeAttestationServer.js';

const LOOPBACK_ADDRESS = '127.0.0.1';

export class NodeRuntimeAttestationListener implements RuntimeAttestationListener {
  private server?: Server;

  constructor(
    private readonly port: number,
    private readonly hostname = LOOPBACK_ADDRESS,
  ) {}

  async listen(handler: RuntimeAttestationFetchHandler): Promise<void> {
    const server = serve({ fetch: handler, port: this.port, hostname: this.hostname });
    if (!(server instanceof Server)) {
      throw new Error('refusing to start: expected an http/1.1 runtime attestation server');
    }
    this.server = server;
    if (!server.listening) await once(server, 'listening');
  }

  async close(): Promise<void> {
    const server = this.server;
    if (!server) return;
    this.server = undefined;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
