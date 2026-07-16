import type {
  ExportCeiling,
  ExportCompleteSignal,
  ExportDueMessage,
  WikiExportTarget,
  WikiExportTargetKind,
} from '@folklore/contracts';
import {
  exportCeilingAccess,
  projectPageForExport,
  defaultRenderers,
  type AudienceAccess,
  type ExportThemeOwner,
  type StoredBlock,
} from '@folklore/wiki';
import type { EncryptedBlockBody, WikiBlockContentRef, WikiContentDecryptor } from '@folklore/api';
import { buildExportClient } from './build-export-client.js';

export interface ExportTargetRecord {
  targetId: string;
  orgId: string;
  themeId: string;
  kind: WikiExportTargetKind;
  ceiling: ExportCeiling;
  // ADL #65 — the ONE audience an above-public export materializes (option B); null = public/all.
  audienceId: string | null;
  acknowledgedAbovePublic: boolean;
  workspaceRef: string;
  pageRef: string | null;
  lastContentHash: string | null;
}

export interface ExportPageSource {
  title: string;
  audienceId: string | null;
  blocks: StoredBlock[];
  /** ADL #49 grant-gate input — the theme's owning department + team. */
  owner: ExportThemeOwner;
  /** The target audience's resolved read access, for a non-public ceiling (option B); null = public/unresolved. */
  audienceAccess?: AudienceAccess | null;
  /** Internal person/system names to redact from the exported page (from identity resolution). */
  internalNames?: string[];
}

/** In-enclave reads over the tenant DB proxy — the same content-free metadata + ciphertext the read path loads. */
export interface WikiExportReader {
  loadTarget(orgId: string, targetId: string): Promise<ExportTargetRecord | null>;
  // audienceId resolves the target audience's access for a non-public ceiling (option B, ADL #65).
  loadPage(
    orgId: string,
    themeId: string,
    audienceId: string | null,
  ): Promise<ExportPageSource | null>;
}

/** Resolves the ECIES-sealed destination token to plaintext, in-enclave only (ADL #42). Never returns to the worker. */
export interface ExportTokenProvider {
  resolveToken(orgId: string, targetId: string, kind: WikiExportTargetKind): Promise<string | null>;
}

export interface ExportRunnerDeps {
  reader: WikiExportReader;
  decryptor: WikiContentDecryptor;
  tokenProvider: ExportTokenProvider;
  buildClient?: (kind: WikiExportTargetKind, token: string) => WikiExportTarget;
}

function isEncryptedBody(body: unknown): body is EncryptedBlockBody {
  return (
    typeof body === 'object' &&
    body !== null &&
    (body as { format?: unknown }).format === 'esdk-v1' &&
    typeof (body as { ciphertext?: unknown }).ciphertext === 'string'
  );
}

/** Runs one content-free `export-due` signal end to end, in-enclave (ADL #65). Null = nothing written. */
export async function runExport(
  message: ExportDueMessage,
  deps: ExportRunnerDeps,
): Promise<ExportCompleteSignal | null> {
  const orgId = message.tenant_id;
  const target = await deps.reader.loadTarget(orgId, message.targetId);
  if (!target) return null;

  // Fail closed: above-public is a one-way declassification that must carry the logged, DB-persisted
  // acknowledgement — never trust the wire, and never export above public without it (ADL #65).
  if (target.ceiling !== 'public' && !target.acknowledgedAbovePublic) return null;

  const page = await deps.reader.loadPage(orgId, target.themeId, target.audienceId);
  if (!page) return null;

  // Fail closed: an above-public ceiling must resolve to exactly ONE audience's access (option B);
  // no resolved audience means we cannot bound the projection, so refuse rather than over-collect.
  const access = exportCeilingAccess(target.ceiling, page.audienceAccess ?? null);
  if (access === null) return null;

  const token = await deps.tokenProvider.resolveToken(orgId, target.targetId, target.kind);
  if (!token) return null;

  const projected = await projectPageForExport({
    themeId: target.themeId,
    title: page.title,
    ceiling: target.ceiling,
    acknowledgedAbovePublic: target.acknowledgedAbovePublic,
    blocks: page.blocks,
    access,
    owner: page.owner,
    decrypt: (block) =>
      decryptStoredBlock(deps.decryptor, orgId, target.themeId, page.audienceId, block),
    renderer: defaultRenderers(),
    redactOptions: page.internalNames ? { names: page.internalNames } : {},
  });

  // Null projection = the theme is hidden to this export's audience (owner grant gate, ADL #49).
  if (!projected) return null;

  // Re-export gate (ADL #65 sync semantics): skip the push when the projection is byte-identical.
  if (projected.contentHash === target.lastContentHash) return null;

  const client = (deps.buildClient ?? buildExportClient)(target.kind, token);
  const ref = await client.upsertPage(projected, {
    workspaceRef: target.workspaceRef,
    pageRef: target.pageRef,
  });

  return {
    type: 'export-complete',
    orgId,
    targetId: target.targetId,
    externalWorkspaceRef: ref.workspaceRef,
    externalPageRef: ref.pageRef,
    contentHash: projected.contentHash,
    exportedAt: new Date().toISOString(),
  };
}

async function decryptStoredBlock(
  decryptor: WikiContentDecryptor,
  orgId: string,
  themeId: string,
  audienceId: string | null,
  block: StoredBlock,
): Promise<unknown | null> {
  if (!isEncryptedBody(block.body)) return block.body;
  const ref: WikiBlockContentRef = { orgId, themeId, audienceId, blockType: block.type };
  return decryptor.decryptBlockBody(ref, block.body);
}
