import type { DecisionAnswer, DecisionQuestion, DecisionResult } from '@folklore/inference';
import { z } from 'zod';
import { TypeSafeDecisionError } from './typesafe-decision-errors.js';

const probabilitySchema = z.number().min(0).max(1);

const answerSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('noul'), noul: probabilitySchema }).strip(),
  z
    .object({
      type: z.literal('choice'),
      choice: z.string(),
      probabilities: z.record(z.string(), probabilitySchema),
    })
    .strip(),
]);

const responseSchema = z
  .object({
    model: z.string(),
    answers: z.record(z.string(), answerSchema),
    usage: z
      .object({
        input_tokens: z.number().int().nonnegative(),
        output_tokens: z.number().int().nonnegative(),
      })
      .strip(),
  })
  .strip();

type WireAnswer = z.infer<typeof answerSchema>;

/** Parses a reply into numbers and option names only, refusing any shape or model the request did not ask for. */
export function parseJevResponse(
  text: string,
  questions: Readonly<Record<string, DecisionQuestion>>,
  pinnedModel: string,
  onUsage: (inputTokens: number, outputTokens: number) => void,
): DecisionResult {
  const parsed = responseSchema.safeParse(parseJson(text));
  if (!parsed.success) throw new TypeSafeDecisionError('typesafe_response_invalid');
  onUsage(parsed.data.usage.input_tokens, parsed.data.usage.output_tokens);
  if (parsed.data.model !== pinnedModel) throw new TypeSafeDecisionError('typesafe_model_mismatch');
  const answers: Record<string, DecisionAnswer> = {};
  for (const [name, question] of Object.entries(questions)) {
    answers[name] = answerFor(question, parsed.data.answers[name]);
  }
  return { model: parsed.data.model, answers };
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new TypeSafeDecisionError('typesafe_response_invalid');
  }
}

function answerFor(question: DecisionQuestion, wire: WireAnswer | undefined): DecisionAnswer {
  if (wire === undefined || wire.type !== question.type) throw invalidResponse();
  if (wire.type === 'noul') return { type: 'noul', pYes: wire.noul };
  if (question.type !== 'choice') throw invalidResponse();
  const options = Object.keys(question.criteria);
  const known = (name: string) => options.includes(name);
  if (!known(wire.choice) || !Object.keys(wire.probabilities).every(known)) {
    throw invalidResponse();
  }
  return { type: 'choice', choice: wire.choice, probabilities: wire.probabilities };
}

function invalidResponse(): TypeSafeDecisionError {
  return new TypeSafeDecisionError('typesafe_response_invalid');
}
