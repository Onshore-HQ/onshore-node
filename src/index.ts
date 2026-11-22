import crypto from "node:crypto";

export interface VaultClientOptions {
  /** Base URL of your vault, for example https://vault.yourbank.ng */
  baseUrl: string;
  serviceAccountId: string;
  keyId: string;
  /** Base64 Ed25519 seed from `rv sa-keygen`. Keep it in your secret store. */
  privateKey: string;
  /** Attempts for retryable failures. Default 4. */
  maxAttempts?: number;
  /** Requests time out after this long. Default 10 seconds. */
  timeoutMs?: number;
  fetch?: typeof fetch;
}

export class VaultError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public policy?: string,
    public requestId?: string,
  ) {
    super(message);
    this.name = "VaultError";
  }
}

export interface TokenizeItem { field: string; value: string; subject_ref?: string }
export interface TokenizeResult { index: number; token?: string; existing?: boolean; error?: { code: string; message: string } }
export interface DetokenizeResult { index: number; decision?: string; value?: string; policy?: string; error?: { code: string; message: string; policy?: string } }

export interface DetokenizeItem { token: string; redaction?: "masked" | "token_only" }

export interface SubjectQuery {
  /** A token, your customer reference, or an exact value (matched through the blind index). */
  query?: string;
  field_type?: string;
  has_reveals?: boolean;
  flagged?: boolean;
  created_after?: string;
  created_before?: string;
  sort?: "created_at" | "field_count" | "last_accessed";
  dir?: "asc" | "desc";
  /** 1 to 200. Default 50. */
  limit?: number;
  offset?: number;
}
export interface SubjectSummary { id: string; ref: string; field_count: number; created_at: string; last_accessed: string | null; reveals_30d: number; restricted: boolean }
export interface SubjectField { field: string; data_type: string; token: string; masked?: string; decision: string; record_id: string }
export interface ExportedField { field: string; data_type: string; value: string; token: string; decision: string }

const BATCH = 500;
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const b64u = (v: string | Buffer) => Buffer.from(v).toString("base64url");

/**
 * Checks a webhook from Onshore. Pass the body exactly as received, before any
 * JSON parsing, and the `x-rv-signature` header. During a secret rotation the header
 * holds two signatures, and either one is enough.
 */
export function verifyWebhook(secret: string, rawBody: string | Buffer, signatureHeader: string, opts: { toleranceSeconds?: number; now?: number } = {}): boolean {
  const parts = (signatureHeader ?? "").split(",").map((p) => p.split("=", 2) as [string, string]);
  const at = Number(parts.find(([k]) => k === "t")?.[1]);
  if (!Number.isInteger(at)) return false;
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - at) > (opts.toleranceSeconds ?? 300)) return false;
  const want = crypto.createHmac("sha256", secret).update(`${at}.`).update(rawBody).digest();
  return parts.filter(([k]) => k === "v1").some(([, v]) => {
    const got = Buffer.from(v ?? "", "hex");
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  });
}

export class VaultClient {
  private key: crypto.KeyObject;
  private token: string | null = null;
  private tokenExpiry = 0;
  private fetchFn: typeof fetch;
  private maxAttempts: number;
  private timeoutMs: number;

  constructor(private opts: VaultClientOptions) {
    this.key = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(opts.privateKey, "base64")]), format: "der", type: "pkcs8" });
    this.fetchFn = opts.fetch ?? fetch;
    this.maxAttempts = opts.maxAttempts ?? 4;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
  }

  private assertion(): string {
    const now = Math.floor(Date.now() / 1000);
    const head = b64u(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: this.opts.keyId }));
    const body = b64u(JSON.stringify({ iss: this.opts.serviceAccountId, sub: this.opts.serviceAccountId, aud: "onshore", jti: crypto.randomUUID(), iat: now, exp: now + 120 }));
    return `${head}.${body}.${b64u(crypto.sign(null, Buffer.from(`${head}.${body}`), this.key))}`;
  }

  private async bearer(): Promise<string> {
    if (this.token && Date.now() < this.tokenExpiry - 60_000) return this.token;
    const r = await this.raw("POST", "/v1/auth/token", { assertion: this.assertion() }, null);
    this.token = r.access_token as string;
    this.tokenExpiry = Date.now() + (r.expires_in as number) * 1000;
    return this.token;
  }

  private async raw(method: string, path: string, body: unknown, token: string | null, headers: Record<string, string> = {}): Promise<Record<string, unknown>> {
    let last: unknown;
    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      if (attempt > 0) await new Promise((r) => setTimeout(r, Math.min(2000, 100 * 2 ** attempt) * (0.5 + Math.random() / 2)));
      let resp: Response;
      try {
        resp = await this.fetchFn(this.opts.baseUrl.replace(/\/$/, "") + path, {
          method,
          headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
      } catch (e) {
        last = new VaultError(0, "network_error", e instanceof Error ? e.name : "request failed");
        continue;
      }
      const data = (await resp.json().catch(() => ({}))) as Record<string, any>;
      if (resp.ok) return data;
      const err = new VaultError(resp.status, data.error?.code ?? "error", data.error?.message ?? `status ${resp.status}`, data.error?.policy, data.request_id);
      if (resp.status === 401 && token) {
        this.token = null;
        throw err;
      }
      if (resp.status === 429 || resp.status >= 500) {
        last = err;
        continue;
      }
      throw err;
    }
    throw last;
  }

  private async call(method: string, path: string, body?: unknown, headers?: Record<string, string>) {
    return this.raw(method, path, body, await this.bearer(), headers);
  }

  /** Stores values and returns tokens. Larger inputs are split into 500-item batches. */
  async tokenize(vault: string, items: TokenizeItem[], opts: { continueOnError?: boolean; dryRun?: boolean } = {}): Promise<TokenizeResult[]> {
    const out: TokenizeResult[] = [];
    for (let i = 0; i < items.length; i += BATCH) {
      const r = await this.call("POST", `/v1/vaults/${vault}/tokenize`, { items: items.slice(i, i + BATCH), continue_on_error: opts.continueOnError ?? false, dry_run: opts.dryRun ?? false });
      for (const x of r.results as TokenizeResult[]) out.push({ ...x, index: x.index + i });
    }
    return out;
  }

  /**
   * Returns values as policy allows. Fails closed: when the vault cannot answer
   * this throws, and it never returns the token as if it were the value.
   */
  async detokenize(vault: string, tokens: (string | DetokenizeItem)[], purpose: string, opts: { continueOnError?: boolean } = {}): Promise<DetokenizeResult[]> {
    const out: DetokenizeResult[] = [];
    for (let i = 0; i < tokens.length; i += BATCH) {
      const items = tokens.slice(i, i + BATCH).map((t) => (typeof t === "string" ? { token: t } : t));
      const r = await this.call("POST", `/v1/vaults/${vault}/detokenize`, { items, purpose, continue_on_error: opts.continueOnError ?? false });
      for (const x of r.results as DetokenizeResult[]) out.push({ ...x, index: x.index + i });
    }
    return out;
  }

  async insertRecord(vault: string, fields: Record<string, string>, subjectRef?: string) {
    return this.call("POST", `/v1/vaults/${vault}/records`, { fields, subject_ref: subjectRef }) as Promise<{ id: string; tokens: Record<string, string> }>;
  }

  /** Reads every field of a record, each as the caller's access rules allow. */
  async getRecord(vault: string, id: string, purpose: string): Promise<Record<string, DetokenizeResult>> {
    return (await this.call("GET", `/v1/vaults/${vault}/records/${encodeURIComponent(id)}`, undefined, { "x-rv-purpose": purpose })).fields as never;
  }

  /** Changes the value behind a new-token-each-time (cell) token. The token stays the same. */
  async updateValue(vault: string, token: string, value: string): Promise<void> {
    await this.call("PUT", `/v1/vaults/${vault}/tokens/${encodeURIComponent(token)}`, { value });
  }

  /** Lists the people in a vault. Needs the `search` action. */
  async searchSubjects(vault: string, query: SubjectQuery = {}): Promise<{ subjects: SubjectSummary[]; total: number }> {
    return this.call("POST", `/v1/vaults/${vault}/subjects/search`, query) as never;
  }

  /** One person and their fields, each masked at most. Never returns real values. */
  async getSubject(vault: string, subjectId: string): Promise<SubjectSummary & { fields: SubjectField[] }> {
    const r = await this.call("GET", `/v1/vaults/${vault}/subjects/${encodeURIComponent(subjectId)}`);
    delete r.request_id;
    return r as never;
  }

  /** Exports one person's fields for an access request, as access rules allow. Needs the `export` action. */
  async exportSubject(vault: string, subjectId: string, purpose: string): Promise<ExportedField[]> {
    return (await this.call("GET", `/v1/vaults/${vault}/subjects/${encodeURIComponent(subjectId)}/export`, undefined, { "x-rv-purpose": purpose })).fields as never;
  }

  /** While restricted, nothing about the person reveals, whatever the access rules say. */
  async restrictSubject(vault: string, subjectId: string, restricted: boolean, purpose: string): Promise<boolean> {
    return (await this.call("POST", `/v1/vaults/${vault}/subjects/${encodeURIComponent(subjectId)}/restrict`, { restricted, purpose })).restricted as boolean;
  }

  /** Finds a token without revealing a value. Rate-limited on the server. */
  async lookup(vault: string, field: string, value: string): Promise<string> {
    return (await this.call("POST", `/v1/vaults/${vault}/lookup`, { field, value })).token as string;
  }

  /**
   * Mints a single-use token for a secure component in a browser. `collect` names fields;
   * `reveal` names tokens and needs a purpose. Call this from your server, never the browser.
   */
  async createClientToken(vault: string, opts: { kind: "collect" | "reveal"; origin: string; fields?: string[]; tokens?: string[]; purpose?: string; onBehalfOf?: string; subjectRef?: string; bindIp?: string; ttlSeconds?: number }) {
    return this.call("POST", `/v1/vaults/${vault}/client-tokens`, { kind: opts.kind, origin: opts.origin, fields: opts.fields, tokens: opts.tokens, purpose: opts.purpose, on_behalf_of: opts.onBehalfOf, subject_ref: opts.subjectRef, bind_ip: opts.bindIp, ttl_seconds: opts.ttlSeconds }) as Promise<{ client_token: string; expires_at: string }>;
  }

  /** Checks a batch before a job sends it somewhere Onshore cannot sit in the path. Only counts are kept. */
  async checkFlow(vault: string, flow: string, text: string): Promise<{ identifiers: number; tokens: number; clean: boolean; by_type: Record<string, number> }> {
    return this.call("POST", `/v1/vaults/${vault}/flows/${flow}/check`, { text }) as never;
  }

  /** Custom entities apply when `vault` is named. `entities` limits to built-in or custom slugs. */
  async detect(text: string, opts: { tokenize?: boolean; vault?: string; entities?: string[]; includeShadow?: boolean } = {}) {
    return this.call("POST", "/v1/detect", { text, tokenize: opts.tokenize ?? false, vault: opts.vault, entities: opts.entities, include_shadow: opts.includeShadow }) as Promise<{ text?: string; ruleset_version?: number; entities: { type: string; start: number; end: number; score: number; custom?: boolean; entity_version?: number; shadow?: boolean }[] }>;
  }

  /**
   * Runs a check in the country and returns only true or false, for example whether
   * a stored name matches one supplied. Needs the `compare` policy action.
   */
  async residentCheck(vault: string, token: string, check: "equals" | "name_match" | "age_at_least" | "amount_at_least", arg: string, purpose: string): Promise<boolean> {
    return (await this.call("POST", `/v1/vaults/${vault}/resident/check`, { token, check, arg, purpose })).result as boolean;
  }

  /**
   * Cloaks text before it goes to a model or any outside service. Pass a saved cloak
   * setting's id, or options inline such as `{ person_name: "synthetic", amount: "band" }`.
   * With `keepDays`, the map back to real values is kept in the vault and `id` returned.
   */
  async cloak(vault: string, text: string, opts: { profileId?: string; options?: Record<string, string>; keepDays?: number } = {}): Promise<{ text: string; changed: Record<string, number>; id?: string }> {
    return this.call("POST", `/v1/vaults/${vault}/cloak`, { text, profile_id: opts.profileId, options: opts.options, keep_days: opts.keepDays }) as never;
  }

  /** Swaps placeholders and stand-in names back, as far as the caller's policy allows. */
  async uncloak(vault: string, id: string, text: string, purpose: string): Promise<{ text: string; decisions: Record<string, string> }> {
    return this.call("POST", `/v1/vaults/${vault}/uncloak`, { id, text, purpose }) as never;
  }

  async deleteTwin(vault: string, id: string) {
    return this.call("DELETE", `/v1/vaults/${vault}/twins/${id}`);
  }

  /** Erases everything held on a person. Needs the `delete` action. Returns how many records went. */
  async eraseSubject(vault: string, subjectId: string, purpose: string): Promise<{ erased_records: number }> {
    return this.call("DELETE", `/v1/vaults/${vault}/subjects/${encodeURIComponent(subjectId)}`, undefined, { "x-rv-purpose": purpose }) as never;
  }
}
