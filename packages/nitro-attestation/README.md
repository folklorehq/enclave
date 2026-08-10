# Nitro attestation verifier provenance

This package verifies AWS Nitro Enclaves attestation documents offline. Production verification uses only the embedded AWS Nitro root certificate; it does not use AIA, the operating-system trust store, or network access.

## AWS Nitro root

- Review date: 2026-07-26
- AWS documentation: <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>
- AWS archive: <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
- Archive SHA-256: `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c`
- `root.pem` SHA-256: `6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0`
- Certificate DER SHA-256: `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`
- Subject and issuer: `C=US, O=Amazon, OU=AWS, CN=aws.nitro-enclaves`
- Validity: `2019-10-28T13:28:05Z` through `2049-10-28T14:28:05Z`
- Public key: NIST P-384
- AWS-published SHA-256 fingerprint: `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`
- SPKI SHA-256: `f2caf5ecc6190b4a8399b78bc58a2bbcd0382375db8a1bfd78a82743874fd225`

Independent OpenSSL and Node.js `X509Certificate` inspection agreed on the subject, issuer, validity, DER digest, SPKI digest, fingerprint, CA status, and P-384 public key. The embedded PEM is byte-for-byte identical to `root.pem` from the reviewed archive.

The `nitro_authentic_success_evidence` test verifies a public AWS-signed Nitro attestation document from `anchorageoss/awsnitroverifier` against this embedded root. Synthetic OpenSSL fixtures remain pinned to negative AWS-root coverage and must not satisfy that evidence gate.

## Runtime dependencies

The direct runtime dependencies were reviewed from registry metadata and independently hashed tarballs before installation. The lockfile resolves one `asn1js` 3.0.10 instance for this package and PKIjs.

| Dependency | Version | License      | License source                                |
| ---------- | ------- | ------------ | --------------------------------------------- |
| `cborg`    | 5.1.7   | Apache-2.0   | <https://www.apache.org/licenses/LICENSE-2.0> |
| `pkijs`    | 3.4.0   | BSD-3-Clause | <https://opensource.org/license/bsd-3-clause> |
| `asn1js`   | 3.0.10  | BSD-3-Clause | <https://opensource.org/license/bsd-3-clause> |

These dependency license references identify upstream terms only. They do not grant a project license for this package.

## Test fixtures

The committed certificate chains and documents are synthetic and contain no customer or operational material. They exercise fail-closed verification paths in automated tests; they are not production attestation evidence.
