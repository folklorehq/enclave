# Folklore Enclave

This repository contains the source code that runs inside the Folklore **Nitro Enclave** — the hardware-isolated compute boundary where all customer data is processed. It is published so that customers and independent auditors can verify what the enclave does with their data.

## What this is

Folklore ingests activity from your connected tools (Slack, GitHub, Linear, etc.) and synthesizes it into audience-tiered wikis. All payload content is encrypted end-to-end before it reaches any Folklore-operated infrastructure. The only place where plaintext exists is inside this enclave, on hardware that Folklore cannot access even with AWS console access.

This repository covers the **trust-verification boundary**: the code that seals and unseals keys, decrypts ingest payloads, and verifies the enclave's own identity to AWS KMS.

## Trust model

```
webhook sender
      │
      │  ECIES-encrypted payload (X25519 + AES-256-GCM)
      ▼
ingest-proxy (Lambda)        ← encrypts to enclave public key; never sees plaintext
      │
      │  encrypted message
      ▼
   SQS queue
      │
      ▼
  Nitro Enclave              ← only place plaintext exists; Folklore cannot introspect
      │ decrypts + processes
      ▼
content-free ProcessedFact   ← what leaves the enclave; no raw content
      │
      ▼
   Postgres / S3
```

**Folklore never holds a decryption key.** The master key is generated inside the enclave using entropy from the NSM hardware module, then sealed with AWS KMS under a PCR-gated key policy. KMS will only return the key to an enclave whose PCR0 (the EIF image hash) matches the policy — meaning any change to the enclave binary invalidates the key. The sealed blob is stored in S3; the plaintext never leaves the enclave heap.

## Cryptographic scheme

### Key sealing (boot)

1. NSM provides 32 bytes of hardware entropy.
2. `keygen.ts` derives a master key and an ingest X25519 keypair via HKDF-SHA256.
3. `seal.ts` seals the master key with KMS: it generates an ephemeral RSA-2048 keypair, embeds the public half in an NSM attestation document, and sends the attestation to KMS. KMS encrypts the response to the ephemeral public key — so the plaintext master key is only ever accessible on the enclave heap, never in transit.
4. The sealed blob is written to S3. The ingest public key is published to SSM Parameter Store so `ingest-proxy` can encrypt to it.
5. On first boot, a 24-word BIP39 recovery phrase is derived and logged once. Folklore never stores it.

### Ingest decryption

`ingest/receiver.ts` implements ECIES:

- Sender (`ingest-proxy`) generates an ephemeral X25519 keypair, performs DH with the enclave's ingest public key, and derives an AES-256-GCM key via HKDF-SHA256 with both public keys bound in the info field (prevents key-confusion and replay).
- The enclave inverts this: DH with the sender's ephemeral key + its own static private key, same HKDF derivation, then AES-256-GCM decryption with auth-tag verification.

The encryption in `ingest-proxy/src/handler.ts` and the decryption in `enclave/src/ingest/receiver.ts` are the two sides of this scheme. They must match exactly — auditors should verify that both sides use the same HKDF info field construction.

### Attestation verification

AWS Nitro Attestation Documents are CBOR-encoded, COSE-signed by the Nitro attestation CA. They contain the PCR values (platform configuration registers) that uniquely identify the EIF image running at the time the document was generated.

KMS key policies reference specific PCR0 values. PCR0 is the SHA-384 hash of the EIF (Enclave Image Format) binary. Folklore publishes the PCR0 from each CI-built EIF alongside the corresponding Git commit. An auditor can:

1. Check out the commit and review the trust-verification source in this repository against the scheme described above.
2. Rebuild the EIF from that source with the enclave build configuration and confirm the resulting PCR0 matches the published value.
3. Confirm the running enclave's attestation document reports that same PCR0 and that the active KMS key policy admits only it.

Because KMS releases the sealed key only to an enclave that measures to the policy's PCR0, a match proves the running enclave is executing the measured build for that commit. The build configuration and the closed product modules are not part of this open trust surface (see "What is not in this repository").

## Repository layout

```
enclave/
  src/
    index.ts          boot sequence and SQS processing loop
    sealing/
      keygen.ts       master key generation and HKDF derivation
      seal.ts         KMS recipient attestation (seal/unseal)
      nsm.ts          NSM attestation document wrapper
    ingest/
      receiver.ts     ECIES payload decryption
    http/             attestation and health endpoints served inside the enclave
    inference/        LLM backend adapters (Phala TEE-attested GPU API)
    crypto/           ESDK envelope encryption for outputs written to S3

  native/
    nsm.c             C binding for the AWS Nitro NSM ioctl interface
    binding.gyp       node-gyp build configuration

ingest-proxy/
  src/
    handler.ts        API Gateway Lambda — ECIES encryption of inbound webhooks

preview-proxy/
  src/
    ssrf.ts           SSRF egress guard — public-unicast-only address allow-list
    preview-fetch.ts  redirect-revalidating fetch for link-preview enrichment
```

**What is not in this repository**: the EIF build configuration, product logic (knowledge synthesis, scoring, model prompts, the ingest pipeline steps), and the HNSW index format. Those are compiled into the EIF and not part of the auditable trust boundary — boot and orchestration files here may reference them by interface even though their implementations are not published.

## What leaves the enclave

The enclave emits `ProcessedFact` DTOs to a separate SQS queue. These contain metadata only — timestamps, source references, relationship edges, vector neighbor lists. They contain no raw content from ingested payloads. The `EnclaveOutputsConsumer` in the worker writes these to Postgres and the graph layer.

Outputs written to S3 (fact bodies, the HNSW index) are re-encrypted with AWS Encryption SDK before leaving the enclave heap, using a customer-specific KMS key.

## Security contact

Security issues: security@folklorehq.com
