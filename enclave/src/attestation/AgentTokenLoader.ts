import {
  AttestedSsmParameterReader,
  type AttestedParameterRead,
} from './AttestedSsmParameterReader.js';
import type {
  AttestedSecretDecryptorPort,
  SsmParameterValuePort,
} from './BootManifestSecretLoader.js';
import type { VerifiedBootManifest } from './BootManifestVerifier.js';

const MAX_AGENT_TOKEN_BYTES = 4 * 1024;
const AGENT_TOKEN_PARAMETER = 'agent-token';

export const agentTokenLoadErrors = {
  reference: 'agent_token_reference_invalid',
  missing: 'agent_token_missing',
  accessDenied: 'agent_token_access_denied',
  identity: 'agent_token_identity_invalid',
  version: 'agent_token_version_invalid',
  value: 'agent_token_value_invalid',
  decrypt: 'agent_token_decrypt_failed',
} as const;

export type AgentTokenManifest = Readonly<{
  resourcePrefixes: Readonly<Pick<VerifiedBootManifest['resourcePrefixes'], 'tenantSsm'>>;
  awsAccountId: string;
  awsRegion: string;
  enclaveOutputKeyKmsKeyArn?: string;
  storageKeyArn: string;
}>;

/** The deployment agent token, which its key releases only to an attested enclave. */
export class AgentTokenLoader {
  private readonly reader: AttestedSsmParameterReader;

  constructor(ssm: SsmParameterValuePort, decryptor: AttestedSecretDecryptorPort) {
    this.reader = new AttestedSsmParameterReader(ssm, decryptor, agentTokenLoadErrors);
  }

  async load(input: {
    manifest: AgentTokenManifest | undefined;
    envPath: string;
  }): Promise<string> {
    const plaintext = await this.reader.read(this.signedRead(input.manifest, input.envPath));
    try {
      if (plaintext.length === 0 || plaintext.length > MAX_AGENT_TOKEN_BYTES) {
        throw new Error(agentTokenLoadErrors.value);
      }
      return plaintext.toString('utf8');
    } finally {
      plaintext.fill(0);
    }
  }

  // The host chooses the env path, so a path the signed manifest does not derive could aim this
  // read at another SecureString the enclave may open, such as the output signing key.
  private signedRead(
    manifest: AgentTokenManifest | undefined,
    envPath: string,
  ): AttestedParameterRead {
    const outputKey = manifest?.enclaveOutputKeyKmsKeyArn;
    if (!manifest || !outputKey || !manifest.awsAccountId || !manifest.awsRegion) {
      throw new Error(agentTokenLoadErrors.reference);
    }
    const path = `${manifest.resourcePrefixes.tenantSsm}${AGENT_TOKEN_PARAMETER}`;
    if (envPath !== path) throw new Error(agentTokenLoadErrors.reference);
    return {
      path,
      awsAccountId: manifest.awsAccountId,
      awsRegion: manifest.awsRegion,
      refusedKeyIds: [outputKey, manifest.storageKeyArn],
    };
  }
}
