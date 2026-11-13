import type { DecisionSite } from '@folklore/contracts';
import type { DecisionQuestion, DecisionRequest, JevStateValue } from '@folklore/inference';
import { canonicalJson, canonicalJsonHash } from '@folklore/utils';
import { TypeSafeDecisionError } from './typesafe-decision-errors.js';

export const JEV_KEY_PLACEHOLDER = '{{key}}';
export const JEV_ITEM_KEY_PATTERN = /^[a-z][a-z0-9]{0,7}$/;
export const JEV_STATE_KEY_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;
const MAX_STATE_DEPTH = 64;

export interface JevQuestionSet {
  readonly site: DecisionSite;
  readonly fixed: Readonly<Record<string, DecisionQuestion>>;
  readonly keyed?: {
    readonly prefix: string;
    readonly stateField: string;
    readonly question: DecisionQuestion;
  };
}

export function jevQuestionSetDigest(set: JevQuestionSet): string {
  return canonicalJsonHash({ site: set.site, fixed: set.fixed, keyed: set.keyed ?? null });
}

/** The keyed question for one item, with the placeholder replaced by the item's backticked state path. */
export function instantiateKeyedQuestion(set: JevQuestionSet, key: string): DecisionQuestion {
  if (set.keyed === undefined || !JEV_ITEM_KEY_PATTERN.test(key)) {
    throw new TypeSafeDecisionError('typesafe_question_unregistered');
  }
  const path = `\`${set.keyed.stateField}.${key}\``;
  return JSON.parse(
    JSON.stringify(set.keyed.question).replaceAll(JEV_KEY_PLACEHOLDER, path),
  ) as DecisionQuestion;
}

type Questions = Readonly<Record<string, DecisionQuestion>>;

export class JevQuestionGuard {
  private readonly setsBySite = new Map<DecisionSite, JevQuestionSet[]>();

  /** Throws unless every set's digest is registered for its site and every registered digest has a set. */
  constructor(sets: readonly JevQuestionSet[], digests: ReadonlyMap<string, DecisionSite>) {
    const seen = new Set<string>();
    for (const set of sets) {
      const digest = jevQuestionSetDigest(set);
      if (digests.get(digest) !== set.site) {
        throw new TypeSafeDecisionError('typesafe_question_unregistered');
      }
      seen.add(digest);
      this.setsBySite.set(set.site, [...(this.setsBySite.get(set.site) ?? []), set]);
    }
    if (seen.size !== digests.size)
      throw new TypeSafeDecisionError('typesafe_question_unregistered');
  }

  /** Refuses unless the questions partition exactly into one registered set per listed site and every state key is Folklore-made; returns the registered questions to send. */
  assertRegistered(request: DecisionRequest): Questions {
    this.assertStateKeys(request.state, 0);
    const candidates = request.sites.map((site) => this.setsBySite.get(site) ?? []);
    const registered = this.firstMatch(candidates, [], request.questions);
    if (registered === undefined) throw new TypeSafeDecisionError('typesafe_question_unregistered');
    return registered;
  }

  private assertStateKeys(value: JevStateValue, depth: number): void {
    if (typeof value !== 'object') return;
    if (depth > MAX_STATE_DEPTH) throw new TypeSafeDecisionError('typesafe_state_key_invalid');
    if (Array.isArray(value)) {
      for (const item of value as readonly JevStateValue[]) this.assertStateKeys(item, depth + 1);
      return;
    }
    for (const [key, child] of Object.entries(value as Record<string, JevStateValue>)) {
      if (!JEV_STATE_KEY_PATTERN.test(key))
        throw new TypeSafeDecisionError('typesafe_state_key_invalid');
      this.assertStateKeys(child, depth + 1);
    }
  }

  private firstMatch(
    candidates: readonly (readonly JevQuestionSet[])[],
    chosen: readonly JevQuestionSet[],
    questions: Questions,
  ): Questions | undefined {
    const [options, ...rest] = candidates;
    if (options === undefined) return this.matches(chosen, questions);
    for (const set of options) {
      const found = this.firstMatch(rest, [...chosen, set], questions);
      if (found !== undefined) return found;
    }
    return undefined;
  }

  private matches(sets: readonly JevQuestionSet[], questions: Questions): Questions | undefined {
    try {
      const expected = new Map<string, DecisionQuestion>();
      for (const set of sets) {
        for (const [name, question] of this.expectedBy(set, questions)) {
          if (expected.has(name)) return undefined;
          expected.set(name, question);
        }
      }
      const names = Object.keys(questions);
      const same =
        names.length > 0 &&
        names.length === expected.size &&
        names.every((name) => this.sameQuestion(expected.get(name), questions[name]));
      return same ? Object.fromEntries(expected) : undefined;
    } catch {
      return undefined;
    }
  }

  private expectedBy(set: JevQuestionSet, questions: Questions): [string, DecisionQuestion][] {
    const entries = Object.entries(set.fixed);
    const { keyed } = set;
    if (keyed === undefined) return entries;
    for (const name of Object.keys(questions)) {
      if (!name.startsWith(keyed.prefix)) continue;
      entries.push([name, instantiateKeyedQuestion(set, name.slice(keyed.prefix.length))]);
    }
    return entries;
  }

  private sameQuestion(
    expected: DecisionQuestion | undefined,
    actual: DecisionQuestion | undefined,
  ): boolean {
    return (
      expected !== undefined &&
      actual !== undefined &&
      canonicalJson(expected) === canonicalJson(actual)
    );
  }
}
