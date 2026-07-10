import { linkPreviewSchema, type LinkPreview } from '@folklore/contracts';
import { parseHtmlPreview, parseOembedPreview, type UrlGuard } from './og-parse.js';
import { SsrfSafeFetcher } from './preview-fetch.js';

const HTML_TYPES = ['text/html', 'application/xhtml+xml'];
const JSON_OEMBED_TYPES = ['application/json+oembed', 'text/json+oembed', 'application/json'];

export class PreviewService {
  constructor(private readonly fetcher: SsrfSafeFetcher) {}

  private readonly guard: UrlGuard = (url) =>
    this.fetcher.assertUrlPublic(url).then(
      () => true,
      () => false,
    );

  async preview(url: string): Promise<LinkPreview | null> {
    try {
      return await this.buildPreview(url);
    } catch {
      return null;
    }
  }

  private async buildPreview(url: string): Promise<LinkPreview | null> {
    const doc = await this.fetcher.fetch(url);
    if (this.isType(doc.contentType, JSON_OEMBED_TYPES)) {
      return this.finalize(
        await parseOembedPreview(this.parseJson(doc.body), doc.finalUrl, this.guard),
      );
    }
    if (!this.isType(doc.contentType, HTML_TYPES)) return null;

    const { preview, oembedHref } = await parseHtmlPreview(doc.body, doc.finalUrl, this.guard);
    const merged = oembedHref ? { ...(await this.followOembed(oembedHref)), ...preview } : preview;
    return this.finalize(merged);
  }

  private async followOembed(href: string): Promise<LinkPreview> {
    try {
      const doc = await this.fetcher.fetch(href);
      if (!this.isType(doc.contentType, JSON_OEMBED_TYPES)) return {};
      return await parseOembedPreview(this.parseJson(doc.body), doc.finalUrl, this.guard);
    } catch {
      return {};
    }
  }

  private finalize(preview: LinkPreview): LinkPreview | null {
    const parsed = linkPreviewSchema.safeParse(preview);
    if (!parsed.success) return null;
    const hasContent = Object.values(parsed.data).some((v) => v !== undefined);
    return hasContent ? parsed.data : null;
  }

  private isType(contentType: string, types: string[]): boolean {
    const base = contentType.split(';', 1)[0]!.trim().toLowerCase();
    return types.includes(base);
  }

  private parseJson(body: string): unknown {
    try {
      return JSON.parse(body);
    } catch {
      return null;
    }
  }
}
