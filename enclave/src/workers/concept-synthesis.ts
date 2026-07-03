import { createHash } from 'node:crypto';
import { embedText, generate } from '../inference/phala.js';

export interface ConceptSynthesisRequest {
  type: 'concept_synthesis';
  requestId: string;
  orgId: string;
  containers: {
    containerId: string;
    label: string;
    team: string;
    factRefs: { factId: string; s3Key: string; occurredAt: string }[];
  }[];
}

interface ConceptOut {
  conceptId: string;
  name: string;
  kind: 'topic' | 'ceremony';
  team: string;
  importance: number;
  tags: string[];
  containerIds: string[];
  factIds: string[];
}

export interface ConceptSynthesisResult {
  type: 'concept_synthesis';
  requestId: string;
  orgId: string;
  concepts: ConceptOut[];
  related: { fromConceptId: string; toConceptId: string; similarity: number }[];
}

export type DecryptBody = (
  s3Key: string,
  ref: { factId: string; orgId: string },
) => Promise<string | null>;

const INTENT_TAGS = [
  'decision',
  'incident',
  'customer_issue',
  'blocker',
  'announcement',
  'ceremony',
  'status_update',
  'question',
  'banter',
  'other',
] as const;
type IntentTag = (typeof INTENT_TAGS)[number];

const TAG_WEIGHT: Record<IntentTag, number> = {
  decision: 1.0,
  incident: 1.0,
  customer_issue: 0.9,
  blocker: 0.8,
  announcement: 0.6,
  question: 0.5,
  status_update: 0.4,
  other: 0.4,
  ceremony: 0.3,
  banter: 0.1,
};

const KW_PATTERNS: Array<[IntentTag, RegExp]> = [
  [
    'ceremony',
    /\b(stand-?up|sprint planning|sprint plan|backlog grooming|grooming|retro(spective)?|sprint review|demo day|daily sync|sprint goal|story points)\b/i,
  ],
  [
    'incident',
    /\b(incident|outage|is down|went down|broke|broken|failing|roll ?back|hotfix|sev[012]|p0|post-?mortem|degraded)\b/i,
  ],
  [
    'decision',
    /\b(we decided|let'?s go with|decision:|agreed to|we'?ll go with|approved|signed? off|final call)\b/i,
  ],
  ['customer_issue', /\b(customer|client|ticket|escalat|refund|sla\b|churn|complaint)\b/i],
  ['blocker', /\b(blocked|blocker|can'?t proceed|waiting on|stuck on)\b/i],
  ['announcement', /\b(announc|shipped|launched|now live|released|rolling out)\b/i],
];

const VENUE_LABELS = new Set(['slack_channel']);
const MIN_FACTS = 5;
const MAX_EMBED_CHARS = 2000;
const NAME_SAMPLE = 12;
const TOPIC_THRESHOLD = 0.82;
const RELATE_THRESHOLD = 0.7;
const SPRINT_MS = 14 * 24 * 60 * 60 * 1000;

interface Doc {
  containerId: string;
  label: string;
  team: string;
  midMs: number;
  tags: IntentTag[];
  factIds: string[];
  bodies: string[];
  vec: number[];
}
interface Cluster {
  conceptId: string;
  kind: 'topic' | 'ceremony';
  team: string;
  members: Doc[];
  centroid: number[];
  tags: Set<IntentTag>;
  name: string;
  importance: number;
}

export async function synthesizeConcepts(
  req: ConceptSynthesisRequest,
  decryptBody: DecryptBody,
): Promise<ConceptSynthesisResult> {
  const docs: Doc[] = [];
  for (const c of req.containers) {
    if (VENUE_LABELS.has(c.label) || c.factRefs.length < MIN_FACTS) continue;
    const bodies = (
      await Promise.all(
        c.factRefs.map((ref) => decryptBody(ref.s3Key, { factId: ref.factId, orgId: req.orgId })),
      )
    ).filter((b): b is string => !!b);
    if (bodies.length === 0) continue;
    const vec = await embedText(bodies.join('\n').slice(0, MAX_EMBED_CHARS)).catch(() => []);
    docs.push({
      containerId: c.containerId,
      label: c.label,
      team: c.team,
      midMs: median(c.factRefs.map((r) => Date.parse(r.occurredAt))),
      tags: await tagContainer(bodies),
      factIds: c.factRefs.map((r) => r.factId),
      bodies,
      vec,
    });
  }

  const clusters = clusterDocs(req.orgId, docs);
  for (const cl of clusters) {
    cl.tags = new Set(cl.members.flatMap((m) => m.tags));
    cl.name =
      cl.kind === 'ceremony'
        ? `${cl.team} — sprint ceremonies (${windowLabel(cl)})`
        : await nameTopic(cl);
    cl.importance = importanceFromTags(cl);
  }

  const related: ConceptSynthesisResult['related'] = [];
  for (let i = 0; i < clusters.length; i++) {
    for (let j = i + 1; j < clusters.length; j++) {
      const s = cosine(clusters[i]!.centroid, clusters[j]!.centroid);
      if (s >= RELATE_THRESHOLD) {
        related.push({
          fromConceptId: clusters[i]!.conceptId,
          toConceptId: clusters[j]!.conceptId,
          similarity: s,
        });
      }
    }
  }

  return {
    type: 'concept_synthesis',
    requestId: req.requestId,
    orgId: req.orgId,
    concepts: clusters.map((cl) => ({
      conceptId: cl.conceptId,
      name: cl.name,
      kind: cl.kind,
      team: cl.team,
      importance: cl.importance,
      tags: [...cl.tags],
      containerIds: cl.members.map((m) => m.containerId),
      factIds: cl.members.flatMap((m) => m.factIds),
    })),
    related,
  };
}

// Ceremonies are recurring events (grouped per team × sprint); topics are knowledge
// (clustered semantically within a team so cross-pod work never merges).
function clusterDocs(orgId: string, docs: Doc[]): Cluster[] {
  const clusters: Cluster[] = [];
  const ceremonies = new Map<string, Doc[]>();
  for (const d of docs) {
    if (d.tags.includes('ceremony')) {
      const key = `${d.team}|${Math.floor(d.midMs / SPRINT_MS)}`;
      (ceremonies.get(key) ?? ceremonies.set(key, []).get(key)!).push(d);
      continue;
    }
    let best: { cl: Cluster; s: number } | null = null;
    for (const cl of clusters) {
      if (cl.kind !== 'topic' || cl.team !== d.team) continue;
      const s = cosine(d.vec, cl.centroid);
      if (s >= TOPIC_THRESHOLD && (!best || s > best.s)) best = { cl, s };
    }
    if (best) mergeInto(best.cl, d);
    else clusters.push(newCluster(orgId, 'topic', d, d.containerId));
  }
  for (const [key, group] of ceremonies) {
    const cl = newCluster(orgId, 'ceremony', group[0]!, key);
    for (const d of group.slice(1)) mergeInto(cl, d);
    clusters.push(cl);
  }
  return clusters;
}

function newCluster(orgId: string, kind: Cluster['kind'], seed: Doc, key: string): Cluster {
  const h = createHash('sha256').update(`${orgId}:${key}`).digest('hex');
  const conceptId = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
  return {
    conceptId,
    kind,
    team: seed.team,
    members: [seed],
    centroid: [...seed.vec],
    tags: new Set(seed.tags),
    name: '',
    importance: 0,
  };
}

function mergeInto(cl: Cluster, d: Doc): void {
  cl.members.push(d);
  const n = cl.members.length;
  cl.centroid = cl.centroid.map((v, i) => (v * (n - 1) + (d.vec[i] ?? 0)) / n);
}

function importanceFromTags(cl: Cluster): number {
  const maxTag = Math.max(...[...cl.tags].map((t) => TAG_WEIGHT[t]), 0.1);
  const facts = cl.members.reduce((n, m) => n + m.factIds.length, 0);
  const structural = Math.min(Math.log1p(facts) / Math.log1p(60), 1);
  return Math.min(1, 0.7 * maxTag + 0.3 * structural);
}

async function tagContainer(bodies: string[]): Promise<IntentTag[]> {
  const text = bodies.join('\n').toLowerCase();
  const kw = new Set<IntentTag>();
  for (const [tag, re] of KW_PATTERNS) if (re.test(text)) kw.add(tag);
  if (kw.size > 0) return [...kw].slice(0, 3);

  const sample = bodies
    .filter((b) => b.length > 20)
    .slice(0, 8)
    .map((b) => `- ${b.slice(0, 160)}`)
    .join('\n');
  if (!sample) return ['other'];
  const prompt = `Classify the primary intent of this thread. Pick 1-2 from: ${INTENT_TAGS.join(', ')}\n${sample}\nJSON only: {"tags":["<tag>"]}`;
  try {
    const parsed = JSON.parse(extractJson(await generate(prompt))) as { tags?: unknown };
    const tags = Array.isArray(parsed.tags)
      ? parsed.tags.filter((t): t is IntentTag =>
          (INTENT_TAGS as readonly string[]).includes(t as string),
        )
      : [];
    if (tags.length > 0) return [...new Set(tags)].slice(0, 2);
  } catch {
    /* keyword-less fallback */
  }
  return ['other'];
}

async function nameTopic(cl: Cluster): Promise<string> {
  const bodies = cl.members.flatMap((m) => m.bodies);
  const sample = bodies
    .filter((b) => b.length > 25)
    .sort((a, b) => b.length - a.length)
    .slice(0, NAME_SAMPLE)
    .map((b) => `- ${b.slice(0, 160)}`)
    .join('\n');
  const prompt = `Team: ${cl.team}. Signals: ${[...cl.tags].join(', ')}.\nReal messages from one thread of work:\n${sample}\n\nName the specific feature/effort/problem (e.g. "Checkout Rate-Limit Incident"). Be specific, not generic. Avoid "meeting", "update", "discussion".\nJSON only: {"name":"<3-6 words, title case>"}`;
  try {
    const parsed = JSON.parse(extractJson(await generate(prompt))) as { name?: unknown };
    if (typeof parsed.name === 'string' && parsed.name.trim())
      return `${cl.team}: ${parsed.name.trim()}`;
  } catch {
    /* fall through */
  }
  return `${cl.team}: ${cl.members[0]?.bodies[0]?.slice(0, 40) ?? 'Activity'}`;
}

function windowLabel(cl: Cluster): string {
  const times = cl.members.map((m) => m.midMs).sort((a, b) => a - b);
  const fmt = (ms: number): string => new Date(ms).toISOString().slice(5, 10);
  return `${fmt(times[0]!)}–${fmt(times[times.length - 1]!)}`;
}

function extractJson(raw: string): string {
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  return start === -1 || end <= start ? '{}' : raw.slice(start, end + 1);
}

function median(xs: number[]): number {
  const s = xs.filter((x) => !Number.isNaN(x)).sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)] ?? 0;
}

function cosine(a: number[], b: number[]): number {
  let d = 0;
  let na = 0;
  let nb = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    d += a[i]! * b[i]!;
    na += a[i]! * a[i]!;
    nb += b[i]! * b[i]!;
  }
  return na && nb ? d / (Math.sqrt(na) * Math.sqrt(nb)) : 0;
}
