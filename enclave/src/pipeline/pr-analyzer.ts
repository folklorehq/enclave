import { generate } from '../inference/phala.js';

export type PrChangeType = 'feat' | 'fix' | 'refactor' | 'chore' | 'docs' | 'test' | 'unknown';

export interface PrFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  patch?: string;
}

export interface PrAnalysis {
  summary: string;
  type: PrChangeType;
  subsystems: string[];
  key_changes: string[];
}

const PATCH_CHAR_LIMIT = 2000;
const MAX_FILES_IN_PROMPT = 40;

function buildPrompt(title: string, body: string | null, files: PrFile[]): string {
  const fileLines = files
    .slice(0, MAX_FILES_IN_PROMPT)
    .map((f) => {
      const patch = f.patch ? `\n${f.patch.slice(0, PATCH_CHAR_LIMIT)}` : '';
      return `${f.status} ${f.filename} (+${f.additions}/-${f.deletions})${patch}`;
    })
    .join('\n\n');

  return [
    'Analyze this GitHub pull request and respond ONLY with valid JSON matching exactly:',
    '{"summary":"one sentence","type":"feat|fix|refactor|chore|docs|test|unknown","subsystems":["max 5 short labels"],"key_changes":["up to 4 bullet points"]}',
    '',
    `Title: ${title}`,
    body ? `Description: ${body.slice(0, 1000)}` : '',
    '',
    'Files changed:',
    fileLines,
  ]
    .filter(Boolean)
    .join('\n');
}

function parseAnalysis(raw: string): PrAnalysis | null {
  const jsonMatch = raw.match(/\{[\s\S]*\}/);
  if (!jsonMatch) return null;
  try {
    const parsed = JSON.parse(jsonMatch[0]) as Partial<PrAnalysis>;
    if (typeof parsed.summary !== 'string') return null;
    return {
      summary: parsed.summary,
      type: parsed.type ?? 'unknown',
      subsystems: Array.isArray(parsed.subsystems) ? parsed.subsystems : [],
      key_changes: Array.isArray(parsed.key_changes) ? parsed.key_changes : [],
    };
  } catch {
    return null;
  }
}

export class PrAnalyzer {
  async analyze(title: string, body: string | null, files: PrFile[]): Promise<PrAnalysis | null> {
    const prompt = buildPrompt(title, body, files);
    try {
      const raw = await generate(prompt);
      return parseAnalysis(raw);
    } catch {
      return null;
    }
  }
}
