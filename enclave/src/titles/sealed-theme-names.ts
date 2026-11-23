import { THEME_NAME_KIND, sealedTitleKey, type SynthesisQueueRequest } from '@folklore/contracts';
import type { TitleCatalogPort, TitleRef } from '@folklore/api';

/** Theme id to sealed name, for the themes the tenant's title index holds. */
export type SealedThemeNames = (
  orgId: string,
  themeIds: readonly string[],
) => Promise<ReadonlyMap<string, string>>;

export function sealedThemeNamesFrom(
  catalog: () => TitleCatalogPort | undefined,
): SealedThemeNames {
  return async (orgId, themeIds) => {
    const current = catalog();
    if (current === undefined || themeIds.length === 0) return new Map();
    const refs: TitleRef[] = themeIds.map((subjectId) => ({ kind: THEME_NAME_KIND, subjectId }));
    const titles = await current.resolve(orgId, refs);
    const names = new Map<string, string>();
    for (const themeId of themeIds) {
      const title = titles.get(sealedTitleKey(THEME_NAME_KIND, themeId));
      if (title !== undefined) names.set(themeId, title);
    }
    return names;
  };
}

// A sealed name replaces a field that reaches only prompts and sealed output. The page's own theme name is not
// replaced: it also titles the article, which crosses the queue readable until article titles are sealed.
export async function withSealedThemeNames(
  request: SynthesisQueueRequest,
  names: SealedThemeNames,
): Promise<SynthesisQueueRequest> {
  if (request.type === 'wiki_synthesis') {
    const ids = request.relatedThemes.map((related) => related.themeId);
    const sealed = await names(request.orgId, ids);
    if (sealed.size === 0) return request;
    return {
      ...request,
      relatedThemes: request.relatedThemes.map((related) => ({
        ...related,
        name: sealed.get(related.themeId) ?? related.name,
      })),
    };
  }
  if (request.type === 'team_onboarding_synthesis') {
    const sealed = await names(
      request.orgId,
      request.themes.map((theme) => theme.themeId),
    );
    if (sealed.size === 0) return request;
    return {
      ...request,
      themes: request.themes.map((theme) => ({
        ...theme,
        name: sealed.get(theme.themeId) ?? theme.name,
      })),
    };
  }
  return request;
}
