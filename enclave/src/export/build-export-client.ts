import { wikiExport } from '@folklore/connectors';
import type { WikiExportTarget, WikiExportTargetKind } from '@folklore/contracts';
import { proxiedExportFetch } from '../egress/proxy.js';

// The outbound mirror of pull-runner's `buildConnector` (ADL #65): both destination clients are
// fetch-based, so they egress through the CONNECT proxy via the explicit proxied fetch. The write
// is blocked fail-closed unless the destination host is on the enclave egress allowlist (ADL #42).
export function buildExportClient(kind: WikiExportTargetKind, token: string): WikiExportTarget {
  const fetchImpl = proxiedExportFetch();
  switch (kind) {
    case 'notion':
      return new wikiExport.NotionExportClient(token, fetchImpl);
    case 'clickup':
      return new wikiExport.ClickUpExportClient(token, fetchImpl);
  }
}
