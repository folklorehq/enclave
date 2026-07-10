import { previewResponseSchema, type LinkPreview } from '@folklore/contracts';

// The embed URL lives inside the encrypted wiki block, so only the enclave can read it.
// The enclave has no arbitrary egress: it asks the parent-EC2 egress proxy (over vsock)
// to fetch + SSRF-vet + parse the URL, and gets back only bounded preview fields (ADL #54).
const PROXY_PORT = process.env['VSOCK_PREVIEW_PROXY_PORT'] ?? '';
const TIMEOUT_MS = Number(process.env['PREVIEW_PROXY_TIMEOUT_MS'] ?? '6000');
const PREVIEW_PATH = '/preview';

export async function fetchLinkPreview(url: string): Promise<LinkPreview | null> {
  if (!PROXY_PORT) return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`http://localhost:${PROXY_PORT}${PREVIEW_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const parsed = previewResponseSchema.safeParse(await res.json());
    return parsed.success ? parsed.data.preview : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
