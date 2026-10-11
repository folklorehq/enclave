/** A refusal whose message stays a fixed code while `reason` names the content-free underlying failure. */
export class OAuthRefusal extends Error {
  constructor(
    code: string,
    readonly reason: string,
  ) {
    super(code);
    this.name = 'OAuthRefusal';
  }
}
