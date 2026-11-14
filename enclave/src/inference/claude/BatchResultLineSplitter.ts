const NEWLINE_BYTE = 0x0a;

/** Splits a byte stream into lines, holding at most one line and dropping any that passes the cap. */
export class BatchResultLineSplitter {
  private held: Uint8Array[] = [];
  private heldBytes = 0;
  private dropping = false;

  constructor(
    private readonly maxLineBytes: number,
    private readonly onOversize: () => void,
  ) {}

  *feed(chunk: Uint8Array): Generator<Buffer> {
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(NEWLINE_BYTE, start);
      this.hold(chunk.subarray(start, newline === -1 ? chunk.length : newline));
      if (newline === -1) return;
      const line = this.release();
      if (line !== undefined) yield line;
      start = newline + 1;
    }
  }

  last(): Buffer[] {
    const line = this.release();
    return line === undefined ? [] : [line];
  }

  private hold(segment: Uint8Array): void {
    if (this.dropping) return;
    if (this.heldBytes + segment.length > this.maxLineBytes) {
      this.held = [];
      this.heldBytes = 0;
      this.dropping = true;
      this.onOversize();
      return;
    }
    this.held.push(segment);
    this.heldBytes += segment.length;
  }

  private release(): Buffer | undefined {
    const line = this.dropping ? undefined : Buffer.concat(this.held, this.heldBytes);
    this.held = [];
    this.heldBytes = 0;
    this.dropping = false;
    return line;
  }
}
