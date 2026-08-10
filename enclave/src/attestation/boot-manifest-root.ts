export const BOOT_MANIFEST_ROOT_KEY_ID = 'offline-root-2026-08';

// External release authority must replace these exact bytes before attested boot can be enabled.

export const BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZhOXXKxe/HUIioyNC4dPc5Hu1ROvp9JACL1aun9aEoI=
-----END PUBLIC KEY-----
`;

const PLACEHOLDER_ROOT_KEY_ID = 'offline-root-2026-08';
const PLACEHOLDER_ROOT_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZhOXXKxe/HUIioyNC4dPc5Hu1ROvp9JACL1aun9aEoI=
-----END PUBLIC KEY-----
`;

export function assertApprovedBootManifestRoot(): void {
  if (
    BOOT_MANIFEST_ROOT_KEY_ID === PLACEHOLDER_ROOT_KEY_ID ||
    BOOT_MANIFEST_ROOT_PUBLIC_KEY_PEM === PLACEHOLDER_ROOT_PUBLIC_KEY_PEM
  ) {
    throw new Error('boot_manifest_root_unapproved');
  }
}
