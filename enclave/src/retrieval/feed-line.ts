import { FEED_LINE_MAX_CHARS } from '@folklore/contracts';
import { clipText, stripInlineMarkdown } from '@folklore/utils/text';

const MAX_LINES = 2;
const TRANSITION_VERBS: Readonly<Record<string, string>> = {
  merged: 'merged',
  closed: 'closed',
  reopened: 'reopened',
  cancelled: 'cancelled',
};
const SOURCE_NAMES: Readonly<Record<string, string>> = {
  github: 'GitHub',
  jira: 'Jira',
  linear: 'Linear',
  slack: 'Slack',
  notion: 'Notion',
  clickup: 'ClickUp',
  intercom: 'Intercom',
};
const HTML_TAG = /<[^>]*>/g;
const BLOCK_PREFIX = /^\s{0,3}(?:#{1,6}\s+|>\s?|[-*+]\s+|\d+\.\s+)/;
const PULL_REQUEST_ENTITY = /^PR#(\d+)$/;
const ISSUE_KEY_ENTITY = /^[A-Z][A-Z0-9]+-\d+$/;
const NUMBERED_ENTITY = /^(?:issue:|#)?(\d+)$/;

/** One short excerpt line from a decrypted fact: the first two lines of a content body, or a template for a state change. */
export function feedLineOf(record: unknown): string | null {
  if (typeof record !== 'object' || record === null) return null;
  const fact = record as Record<string, unknown>;
  const text = fact['kind'] === 'transition' ? transitionLine(fact) : contentLine(fact);
  return text === null || text === '' ? null : clipText(text, FEED_LINE_MAX_CHARS);
}

function contentLine(fact: Record<string, unknown>): string | null {
  const content = fact['content'];
  const body =
    typeof content === 'object' && content !== null
      ? (content as Record<string, unknown>)['body']
      : null;
  if (typeof body !== 'string') return null;
  const lines = body
    .split(/\r?\n/)
    .map(plainLine)
    .filter((line) => line !== '');
  return lines.slice(0, MAX_LINES).join(' ');
}

function plainLine(line: string): string {
  return stripInlineMarkdown(line.replace(HTML_TAG, '').replace(BLOCK_PREFIX, ''));
}

function transitionLine(fact: Record<string, unknown>): string | null {
  const transition = fact['transition'];
  const type =
    typeof transition === 'object' && transition !== null
      ? (transition as Record<string, unknown>)['transitionType']
      : null;
  const verb = typeof type === 'string' ? TRANSITION_VERBS[type] : undefined;
  if (verb === undefined) return null;
  return `${subjectOf(fact)} ${verb}`;
}

function subjectOf(fact: Record<string, unknown>): string {
  const entities = Array.isArray(fact['entities']) ? fact['entities'] : [];
  for (const entity of entities) {
    const subject = typeof entity === 'string' ? formatEntity(entity) : null;
    if (subject !== null) return subject;
  }
  return `${sourceName(fact['sourceFactId'])} item`;
}

function formatEntity(entity: string): string | null {
  const pullRequest = PULL_REQUEST_ENTITY.exec(entity);
  if (pullRequest) return `PR #${pullRequest[1]}`;
  if (ISSUE_KEY_ENTITY.test(entity)) return entity;
  const numbered = NUMBERED_ENTITY.exec(entity);
  return numbered ? `#${numbered[1]}` : null;
}

function sourceName(sourceFactId: unknown): string {
  const prefix = typeof sourceFactId === 'string' ? (sourceFactId.split(':')[0] ?? '') : '';
  return SOURCE_NAMES[prefix] ?? 'Source';
}
