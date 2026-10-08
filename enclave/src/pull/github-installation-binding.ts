import { z } from 'zod';

const BINDING_VERSION = 1;

const gitHubInstallationBindingSchema = z
  .object({
    version: z.literal(BINDING_VERSION),
    installationId: z
      .string()
      .regex(/^[0-9]+$/)
      .max(32),
  })
  .strict();

export class GitHubInstallationBindingError extends Error {
  constructor() {
    super('github_installation_binding_mismatch');
    this.name = 'GitHubInstallationBindingError';
  }
}

/** The plaintext sealed as a GitHub connection's credential: the installation proven at connect. */
export function gitHubInstallationBindingPlaintext(installationId: string): Buffer {
  const binding = gitHubInstallationBindingSchema.parse({
    version: BINDING_VERSION,
    installationId,
  });
  return Buffer.from(JSON.stringify(binding), 'utf8');
}

/** The sealed installation id, refusing when the control plane's projection names another. */
export function boundGitHubInstallationId(
  sealedCredential: string,
  projectedInstallationId: string | undefined,
): string {
  let installationId: string;
  try {
    installationId = gitHubInstallationBindingSchema.parse(
      JSON.parse(sealedCredential),
    ).installationId;
  } catch {
    throw new GitHubInstallationBindingError();
  }
  if (projectedInstallationId !== installationId) throw new GitHubInstallationBindingError();
  return installationId;
}
