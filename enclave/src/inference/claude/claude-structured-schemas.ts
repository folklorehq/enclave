import type { ToolSpec } from '@folklore/inference';
import { canonicalJsonHash } from '@folklore/utils';
import { DOC_TYPES } from '@folklore/wiki';
import { ClaudeRouteError } from './claude-route-errors.js';

export const CLAUDE_STRUCTURED_SCHEMA_DIGESTS: ReadonlyMap<string, string> = new Map([
  ['report_relevance', '6aed7bc1e658ca937c7a1b060c55a62d0df656aef75e673fda168a7d0fd7e56b'],
  ['fix_graph_block', 'a1c8cc02f708334c2040ed5c9f538f5f9f9a4855a23d7c1ceed8b50474001831'],
  ['fix_chart_block', '1f8727b9e8ea990aaff32a2fb89a546d1896bae28e9fd9b110d2e716f3995fc7'],
  ['report_same_concept', 'cf3eff456c35d8ac5afe2c85832abc2d8b32ea540c3a57ea533daadb1d0ed39b'],
  ['report_association', 'c39610d19beea31937d6bdffa1e1e1ef3d64fc4dbf30401b6bb45c393a2da722'],
  ['report_theme_relation', '88336179de0b8e56dd4f1235e922f9d9d616bfc34610b7e9ebd5388588c8af1f'],
  ['report_visual_warrant', '40286383c4f56fd4928a123fa7219311c1db75e19b45607709e0efd6f86d8800'],
  ['report_support', '668edccaf60c0164199450ae5825638db3ff67f00d8a510d41687ea1c7f287b9'],
  ['report_page_issues', '532b7a1bfec835d4896739e7626bccc30a656a25260abc3e5a733b48fb073e9d'],
  ['report_page_check', 'ca6fca3011faece0ed194bb29f258153e47672f36118b65fe8fdfb34dd09994a'],
  ['report_article_check', '1f2e30dd00c17d67e99eefb9408c8a9a1bd9ba2b29588a6c69b33b82a8074cab'],
  ['plan_page_outline', '68fad120b2d3e65e4581ac9817024201932e98c5ea1230b586417e90d61021fd'],
]);

export const PAGE_OUTLINE_TOOL_NAME = 'plan_page_outline';

type OutlineParameters = {
  properties?: { sections?: { items?: { properties?: { type?: { enum?: unknown } } } } };
};

function outlineTypeOf(parameters: unknown): { enum?: unknown } | undefined {
  return (parameters as OutlineParameters).properties?.sections?.items?.properties?.type;
}

// The outline's section types come from the compiled template per call, so the registry pins the shape and not the list.
function withoutOutlineTypes(parameters: unknown): unknown {
  const copy = JSON.parse(JSON.stringify(parameters)) as OutlineParameters;
  const type = outlineTypeOf(copy);
  if (type !== undefined) type.enum = [];
  return copy;
}

// The digest erases the list, so the list is held to the section types some template declares.
function outlineTypesAreDeclared(tool: ToolSpec): boolean {
  const listed = outlineTypeOf(tool.parameters)?.enum;
  if (!Array.isArray(listed)) return false;
  const declared = new Set(
    Object.values(DOC_TYPES).flatMap((spec) => spec.sections.map((section) => section.type)),
  );
  return listed.every((type) => typeof type === 'string' && declared.has(type));
}

export function structuredSchemaDigest(tool: ToolSpec): string {
  const parameters =
    tool.name === PAGE_OUTLINE_TOOL_NAME ? withoutOutlineTypes(tool.parameters) : tool.parameters;
  return canonicalJsonHash({ name: tool.name, parameters });
}

export function assertRegisteredSchema(tool: ToolSpec): void {
  const registered =
    CLAUDE_STRUCTURED_SCHEMA_DIGESTS.get(tool.name) === structuredSchemaDigest(tool);
  const typesDeclared = tool.name !== PAGE_OUTLINE_TOOL_NAME || outlineTypesAreDeclared(tool);
  if (!registered || !typesDeclared) {
    throw new ClaudeRouteError('claude_structured_schema_unregistered');
  }
}

// The output format accepts only closed objects, so the registered schema is closed on the way out.
export function closedOutputSchema(schema: unknown): unknown {
  if (Array.isArray(schema)) return schema.map(closedOutputSchema);
  if (typeof schema !== 'object' || schema === null) return schema;
  const entries = Object.entries(schema).map(([key, value]) => [key, closedOutputSchema(value)]);
  const closed = Object.fromEntries(entries) as Record<string, unknown>;
  if (closed['type'] === 'object' && closed['additionalProperties'] === undefined) {
    closed['additionalProperties'] = false;
  }
  return closed;
}
