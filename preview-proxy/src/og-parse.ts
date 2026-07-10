import { PREVIEW_DESCRIPTION_MAX, PREVIEW_TITLE_MAX, type LinkPreview } from '@folklore/contracts';

const MAX_URL_CHARS = 2048;

export type UrlGuard = (url: string) => Promise<boolean>;

export interface ParsedHtml {
  preview: LinkPreview;
  oembedHref: string | null;
}

interface Tag {
  name: string;
  attrs: Map<string, string>;
}

const TAG = /<(meta|link|title)\b([^>]*)>([\s\S]*?<\/title>)?/gi;
const ATTR = /([a-zA-Z][\w:-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
const TITLE_TEXT = /<title\b[^>]*>([\s\S]*?)<\/title>/i;

const ENTITIES: Record<string, string> = {
  '&amp;': '&',
  '&quot;': '"',
  '&#39;': "'",
  '&apos;': "'",
  '&lt;': '<',
  '&gt;': '>',
  '&nbsp;': ' ',
};

export async function parseHtmlPreview(
  html: string,
  baseUrl: string,
  guard: UrlGuard,
): Promise<ParsedHtml> {
  const tags = collectTags(html);
  const meta = metaMap(tags);

  const title = firstDefined(meta.get('og:title'), meta.get('twitter:title'), titleTag(html));
  const description = firstDefined(
    meta.get('og:description'),
    meta.get('twitter:description'),
    meta.get('description'),
  );
  const image = firstDefined(
    meta.get('og:image:secure_url'),
    meta.get('og:image'),
    meta.get('twitter:image'),
    meta.get('twitter:image:src'),
  );

  const preview: LinkPreview = {};
  const boundedTitle = bound(title, PREVIEW_TITLE_MAX);
  if (boundedTitle) preview.title = boundedTitle;
  const boundedDescription = bound(description, PREVIEW_DESCRIPTION_MAX);
  if (boundedDescription) preview.description = boundedDescription;
  const imageUrl = await guardedUrl(image, baseUrl, guard);
  if (imageUrl) preview.imageUrl = imageUrl;
  const faviconUrl = await faviconFrom(tags, baseUrl, guard);
  if (faviconUrl) preview.faviconUrl = faviconUrl;

  return { preview, oembedHref: oembedFrom(tags, baseUrl) };
}

export async function parseOembedPreview(
  json: unknown,
  baseUrl: string,
  guard: UrlGuard,
): Promise<LinkPreview> {
  if (!json || typeof json !== 'object') return {};
  const record = json as Record<string, unknown>;
  const preview: LinkPreview = {};
  const title = bound(asString(record['title']), PREVIEW_TITLE_MAX);
  if (title) preview.title = title;
  const description = bound(asString(record['author_name']), PREVIEW_DESCRIPTION_MAX);
  if (description) preview.description = description;
  const image = await guardedUrl(asString(record['thumbnail_url']), baseUrl, guard);
  if (image) preview.imageUrl = image;
  return preview;
}

function collectTags(html: string): Tag[] {
  const tags: Tag[] = [];
  for (const match of html.matchAll(TAG)) {
    const name = (match[1] ?? '').toLowerCase();
    const attrs = new Map<string, string>();
    for (const attr of (match[2] ?? '').matchAll(ATTR)) {
      const key = (attr[1] ?? '').toLowerCase();
      const value = attr[3] ?? attr[4] ?? attr[5] ?? '';
      attrs.set(key, decodeEntities(value.trim()));
    }
    tags.push({ name, attrs });
  }
  return tags;
}

function metaMap(tags: Tag[]): Map<string, string> {
  const meta = new Map<string, string>();
  for (const tag of tags) {
    if (tag.name !== 'meta') continue;
    const key = (tag.attrs.get('property') ?? tag.attrs.get('name'))?.toLowerCase();
    const content = tag.attrs.get('content');
    if (key && content && !meta.has(key)) meta.set(key, content);
  }
  return meta;
}

function titleTag(html: string): string | undefined {
  const match = TITLE_TEXT.exec(html);
  return match ? decodeEntities(match[1]!.trim()) : undefined;
}

async function faviconFrom(
  tags: Tag[],
  baseUrl: string,
  guard: UrlGuard,
): Promise<string | undefined> {
  const iconRels = new Set(['icon', 'shortcut icon', 'apple-touch-icon']);
  for (const tag of tags) {
    if (tag.name !== 'link') continue;
    const rel = tag.attrs.get('rel')?.toLowerCase() ?? '';
    if (!iconRels.has(rel)) continue;
    const href = await guardedUrl(tag.attrs.get('href'), baseUrl, guard);
    if (href) return href;
  }
  return guardedUrl(defaultFavicon(baseUrl), baseUrl, guard);
}

function defaultFavicon(baseUrl: string): string | undefined {
  try {
    const origin = new URL(baseUrl);
    if (origin.protocol !== 'http:' && origin.protocol !== 'https:') return undefined;
    return `${origin.protocol}//${origin.host}/favicon.ico`;
  } catch {
    return undefined;
  }
}

function oembedFrom(tags: Tag[], baseUrl: string): string | null {
  for (const tag of tags) {
    if (tag.name !== 'link') continue;
    const type = tag.attrs.get('type')?.toLowerCase() ?? '';
    if (type !== 'application/json+oembed' && type !== 'text/json+oembed') continue;
    const href = safeAbsoluteUrl(tag.attrs.get('href'), baseUrl);
    if (href) return href;
  }
  return null;
}

async function guardedUrl(
  value: string | undefined,
  baseUrl: string,
  guard: UrlGuard,
): Promise<string | undefined> {
  const href = safeAbsoluteUrl(value, baseUrl);
  if (!href) return undefined;
  return (await guard(href)) ? href : undefined;
}

function safeAbsoluteUrl(value: string | undefined, baseUrl: string): string | undefined {
  if (!value) return undefined;
  try {
    const resolved = new URL(value, baseUrl);
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return undefined;
    const href = resolved.toString();
    return href.length <= MAX_URL_CHARS ? href : undefined;
  } catch {
    return undefined;
  }
}

function decodeEntities(value: string): string {
  return value
    .replace(/&#(\d+);/g, (_m, code: string) => String.fromCodePoint(Number(code)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, code: string) => String.fromCodePoint(parseInt(code, 16)))
    .replace(/&[a-zA-Z]+;|&#39;|&apos;/g, (entity) => ENTITIES[entity] ?? entity);
}

function firstDefined(...values: (string | undefined)[]): string | undefined {
  for (const value of values) if (value && value.trim().length > 0) return value.trim();
  return undefined;
}

function bound(value: string | undefined, max: number): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  return trimmed.length <= max ? trimmed : trimmed.slice(0, max);
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}
