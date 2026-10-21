export interface OpenAIEmbedRouteIdentity {
  readonly enabled: boolean;
  readonly organizationIdSha256: string;
  readonly projectIdSha256: string;
  readonly model: string;
  readonly dimensions: number;
}

// prettier-ignore
export const OPENAI_EMBED_ROUTE_IDENTITY: OpenAIEmbedRouteIdentity = {"enabled":true,"organizationIdSha256":"c80da59dacff980bc869a4530fb98db7fe43eca51af12c802c9bf4c6621745e5","projectIdSha256":"65f04ddc37b59a63bf16a91d67e40cdb27931d6e428018b35736d73e2a8a5c80","model":"text-embedding-3-large","dimensions":1536};
