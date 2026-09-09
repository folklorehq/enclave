import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { z } from 'zod';

export const DSTACK_PUBLIC_NATIVE_INPUT_MAX_BYTES = 8_388_608;
export const DSTACK_PUBLIC_NATIVE_OUTPUT_MAX_BYTES = 65_536;
export const DSTACK_PUBLIC_NATIVE_TIMEOUT_MS = 2_000;

const hex64 = /^[0-9a-f]{64}$/;
const hex96 = /^[0-9a-f]{96}$/;
const hex128 = /^[0-9a-f]{128}$/;
const base64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const inputSchema = z
  .object({
    version: z.literal(2),
    quoteBase64: z.string().regex(base64),
    collateralBase64: z.string().regex(base64),
    eventLog: z.string(),
    vmConfig: z.string(),
    evaluationTimeUnixSeconds: z.number().int().nonnegative(),
  })
  .strict();
const outputSchema = z
  .object({
    version: z.literal(2),
    verdict: z.enum(['accepted', 'rejected']),
    failureCode: z.enum([
      'none',
      'malformed_input',
      'quote_verification_failed',
      'event_log_verification_failed',
      'report_data_unavailable',
      'unsupported_tee',
      'unavailable',
    ]),
    quoteDigestHex: z.string().regex(hex64),
    collateralDigestHex: z.string().regex(hex64),
    eventLogDigestHex: z.string().regex(hex64),
    vmConfigDigestHex: z.string().regex(hex64),
    quoteRootDigestHex: z.string().regex(hex64),
    reportDataHex: z.string().regex(hex128),
    teeVariant: z.string().min(1),
    tcbStatus: z.string().min(1),
    advisoryIds: z.array(z.string()),
    mrTdHex: z.string().regex(hex96),
    rtmr0Hex: z.string().regex(hex96),
    rtmr1Hex: z.string().regex(hex96),
    rtmr2Hex: z.string().regex(hex96),
    rtmr3Hex: z.string().regex(hex96),
    replayedRtmr3Hex: z.string().regex(hex96),
    appInfo: z
      .object({
        appIdHex: z.string().regex(/^[0-9a-f]{40}$/),
        instanceIdHex: z.string().regex(/^[0-9a-f]{40}$/),
        composeHashHex: z.string().regex(hex64),
        keyProviderInfoDigestHex: z.string().regex(hex64),
      })
      .strict(),
    keyProvider: z.object({ name: z.string(), id: z.string() }).strict().optional(),
  })
  .strict();

export interface DstackPublicNativeInput {
  quoteBase64: string;
  collateralBase64: string;
  eventLog: string;
  vmConfig: string;
  evaluationTimeUnixSeconds: number;
}
export type DstackPublicNativeResult = z.infer<typeof outputSchema>;
export interface DstackPublicNativeVerifierOptions {
  executablePath: string;
  args?: readonly string[];
  cwd?: string;
  timeoutMs?: number;
  nowUnixSeconds: () => number;
  quoteRootDigestHex: string;
  expectedTcbStatus: string;
  expectedMrTdHex?: string;
  expectedRtmrHex?: readonly [string, string, string, string];
}

export class DstackPublicNativeVerifier {
  readonly #options: DstackPublicNativeVerifierOptions;
  public constructor(options: DstackPublicNativeVerifierOptions) {
    if (!options || !options.executablePath || !options.executablePath.startsWith('/'))
      throw new Error('dstack_public_executable_invalid');
    if (!hex64.test(options.quoteRootDigestHex) || !options.expectedTcbStatus)
      throw new Error('dstack_public_pins_invalid');
    if (
      !Number.isInteger(options.timeoutMs ?? DSTACK_PUBLIC_NATIVE_TIMEOUT_MS) ||
      (options.timeoutMs ?? DSTACK_PUBLIC_NATIVE_TIMEOUT_MS) <= 0 ||
      (options.timeoutMs ?? DSTACK_PUBLIC_NATIVE_TIMEOUT_MS) > DSTACK_PUBLIC_NATIVE_TIMEOUT_MS
    )
      throw new Error('dstack_public_timeout_invalid');
    this.#options = options;
  }
  public async verify(
    input: DstackPublicNativeInput,
  ): Promise<DstackPublicNativeResult | undefined> {
    const parsed = inputSchema.safeParse({ version: 2, ...input });
    if (!parsed.success || parsed.data.evaluationTimeUnixSeconds !== this.#options.nowUnixSeconds())
      return undefined;
    const body = Buffer.from(JSON.stringify(parsed.data));
    if (body.byteLength > DSTACK_PUBLIC_NATIVE_INPUT_MAX_BYTES) return undefined;
    const response = await this.#run(this.frame(body));
    if (!response) return undefined;
    const decoded = this.parseFrame(response);
    if (!decoded) return undefined;
    let value: unknown;
    try {
      value = JSON.parse(decoded);
    } catch {
      return undefined;
    }
    if (this.hasDuplicateKeys(decoded)) return undefined;
    const native = outputSchema.safeParse(value);
    if (!native.success) return undefined;
    if (native.data.failureCode !== 'none' || native.data.verdict !== 'accepted') return undefined;
    return this.#matches(native.data, parsed.data) ? native.data : undefined;
  }
  #matches(value: z.infer<typeof outputSchema>, input: z.infer<typeof inputSchema>): boolean {
    const digest = (data: string | Buffer): string =>
      createHash('sha256').update(data).digest('hex');
    const rtmr = this.#options.expectedRtmrHex;
    return (
      value.quoteDigestHex === digest(Buffer.from(input.quoteBase64, 'base64')) &&
      value.collateralDigestHex === digest(Buffer.from(input.collateralBase64, 'base64')) &&
      value.eventLogDigestHex === digest(input.eventLog) &&
      value.vmConfigDigestHex === digest(input.vmConfig) &&
      value.quoteRootDigestHex === this.#options.quoteRootDigestHex &&
      value.tcbStatus === this.#options.expectedTcbStatus &&
      value.replayedRtmr3Hex === value.rtmr3Hex &&
      (!this.#options.expectedMrTdHex || value.mrTdHex === this.#options.expectedMrTdHex) &&
      (!rtmr ||
        [value.rtmr0Hex, value.rtmr1Hex, value.rtmr2Hex, value.rtmr3Hex].every(
          (v, i) => v === (rtmr[i] ?? ''),
        ))
    );
  }
  #run(input: Buffer): Promise<Buffer | undefined> {
    return new Promise((resolve) => {
      let child;
      try {
        child = spawn(this.#options.executablePath, [...(this.#options.args ?? [])], {
          cwd: this.#options.cwd,
          env: { PATH: process.env.PATH },
          stdio: ['pipe', 'pipe', 'ignore'],
        });
      } catch {
        resolve(undefined);
        return;
      }
      const chunks: Buffer[] = [];
      let total = 0;
      let done = false;
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, this.#options.timeoutMs ?? DSTACK_PUBLIC_NATIVE_TIMEOUT_MS);
      const finish = (v?: Buffer) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve(v);
      };
      child.stdout.on('data', (chunk: Buffer) => {
        total += chunk.length;
        if (total > DSTACK_PUBLIC_NATIVE_OUTPUT_MAX_BYTES + 4) {
          child.kill('SIGKILL');
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      child.once('error', () => {
        child.kill('SIGKILL');
      });
      child.once('close', (code) =>
        finish(!timedOut && code === 0 ? Buffer.concat(chunks, total) : undefined),
      );
      child.stdin.once('error', () => {
        child.kill('SIGKILL');
      });
      child.stdin.end(input);
    });
  }

  private frame(body: Buffer): Buffer {
    const result = Buffer.allocUnsafe(body.length + 4);
    result.writeUInt32BE(body.length, 0);
    body.copy(result, 4);
    return result;
  }
  private parseFrame(value: Buffer): string | undefined {
    if (value.length < 4) return undefined;
    const length = value.readUInt32BE(0);
    if (!length || length > DSTACK_PUBLIC_NATIVE_OUTPUT_MAX_BYTES || value.length !== length + 4)
      return undefined;
    const decoder = new TextDecoder('utf-8', { fatal: true });
    try {
      return decoder.decode(value.subarray(4));
    } catch {
      return undefined;
    }
  }
  private hasDuplicateKeys(json: string): boolean {
    const objects: Set<string>[] = [];
    for (let index = 0; index < json.length; index += 1) {
      const character = json[index];
      if (character === '{') {
        objects.push(new Set());
        continue;
      }
      if (character === '}') {
        objects.pop();
        continue;
      }
      if (character !== '"' || objects.length === 0) continue;
      const end = this.readStringEnd(json, index);
      if (end < 0) return true;
      if (/^\s*:/.test(json.slice(end + 1))) {
        const key = JSON.parse(`"${json.slice(index + 1, end)}"`) as string;
        const current = objects[objects.length - 1];
        if (current?.has(key)) return true;
        current?.add(key);
      }
      index = end;
    }
    return false;
  }

  private readStringEnd(json: string, start: number): number {
    let escaped = false;
    for (let index = start + 1; index < json.length; index += 1) {
      const character = json[index];
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') return index;
    }
    return -1;
  }
}
