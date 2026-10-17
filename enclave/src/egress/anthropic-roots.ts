import { X509Certificate, createHash } from 'node:crypto';
import { rootCertificates } from 'node:tls';

export const ANTHROPIC_ROOT_SET_MISMATCH = 'anthropic_tls_root_set_mismatch';

export const ANTHROPIC_ROOT_SPKI_SHA256: readonly string[] = Object.freeze([
  '0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3',
  '0e8bb18bbeefb381be21bfc1a206d317298462ad104855f04a0542699708d3d4',
  '15eed339594b304f8cf847b477371d8d6fec61f4db2b01af589e7c53b35cae4c',
  '1bf00d5c8f13c094dd17e00504cf0888850f12fd067fa1f92c0fdbf60b86e321',
  '2021917e98263945c859c43f1d73cb4139053c414fa03ca3bc7ee88614298f3b',
  '2bcf553a66f570900ddd32ba6dfe1ecc06c9182d662dc1b60e1f7b767c2bdd54',
  '348767cdad3bdd28b2b8dd5351aec30c68cec5cd69d276df3827dbc4f5806464',
  '4179edd981ef747477b49626408af43daa2ca7ab7f9e082c1060f84096774348',
  '59df317bfa9f4f0ab7ca514d7772296aa2c765b87664d08b96e57399e364729c',
  '6a97b51c8219e93e5dec64bad5806cdeb0f8355be47e757010b702456e01aafd',
  '762195c225586ee6c0237456e2107dc54f1efc21f61a792ebd515913cce68332',
  '7cd67c248f69d83fc2f9bb01dcb1f7ad67a363d046043796d0984c3a231f6bb0',
  '82b5f84daf47a59c7ab521e4982aefa40a53406a3aec26039efa6b2e0e7244c1',
  '871a9194f4eed5b312ff40c84c1d524aed2f778bbff25f138cf81f680a7adc67',
  '8bb593a93be1d0e8a822bb887c547890c3e706aad2dab76254f97fb36b82fc26',
  '9847e5653e5e9e847516e5cb818606aa7544a19be67fd7366d506988e8d84347',
  'a02fafa192c8cb81cb1341554f9c05b71cca2a890b0d1298d683647c961efbdf',
  'a320f4d534d7be97c1ae8dd0499735bc895c323add2d388bfccf662c23d7f99a',
  'b0b56335468561f5bb9fa12d801784a633a572705d34f32b643445dfa8b005d1',
  'b94c198300cec5c057ad0727b70bbe91816992256439a7b32f4598119dda9c97',
  'c784333d20bcd742b9fdc3236f4e509b8937070e73067e254dd3bf9c45bf4dde',
  'd1c45377ebdcd618cd1651dc2e02c21d751e5aa9fcd1b3431ff6ecf6a31348fa',
  'e7ca91bbfbb18788057b3a8070446ea5291160194102f7dcc3b9848c63cb9cd5',
  'f1c6ba670cfc88e4df52973cae420f0a089dd474144fe5806c420064e1591229',
]);

export function spkiSha256Of(pem: string): string {
  const certificate = new X509Certificate(pem);
  return createHash('sha256')
    .update(certificate.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
}

export function selectAnthropicRootPems(
  pems: readonly string[] = rootCertificates,
  spkis: readonly string[] = ANTHROPIC_ROOT_SPKI_SHA256,
): string[] {
  const wanted = new Set(spkis);
  const selected = new Map<string, string>();
  for (const pem of pems) {
    const spki = spkiSha256Of(pem);
    if (!wanted.has(spki)) continue;
    if (selected.has(spki)) throw new Error(ANTHROPIC_ROOT_SET_MISMATCH);
    selected.set(spki, pem);
  }
  if (spkis.length === 0 || selected.size !== wanted.size || wanted.size !== spkis.length) {
    throw new Error(ANTHROPIC_ROOT_SET_MISMATCH);
  }
  return [...selected.values()];
}
