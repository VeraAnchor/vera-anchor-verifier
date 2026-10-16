/** Bounded, credential-free transport for fixed Explorer public API paths. */
export type ExplorerPublicTransportV1 = Readonly<{
  base_url: string;
  fetch_impl?: typeof fetch;
  timeout_ms?: number;
  max_response_bytes?: number;
}>;

export type ExplorerPublicHttpResultV1 = Readonly<{
  status: "ok" | "not_found" | "unavailable" | "invalid";
  reason_code: string | null;
  body: unknown | null;
}>;

const MAX_BYTES = 512 * 1024;
const DEFAULT_TIMEOUT = 15_000;

function origin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("Explorer base_url must be an absolute URL");
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if ((url.protocol !== "https:" && !(local && url.protocol === "http:")) ||
    url.username || url.password || url.search || url.hash ||
    (url.pathname !== "/" && url.pathname !== "/v1" && url.pathname !== "/v1/")) {
    throw new TypeError("Explorer base_url must identify a fixed HTTPS origin (HTTP loopback permitted)");
  }
  return url.origin;
}

/** Only code-defined paths are accepted. No evidence-controlled URL resolution. */
export async function readExplorerPublicV1(
  config: ExplorerPublicTransportV1,
  path: string,
  network: "mainnet" | "testnet",
  postBody?: Readonly<Record<string, unknown>>,
  query?: Readonly<{ resultId?: string }>,
): Promise<ExplorerPublicHttpResultV1> {
  const base = origin(config.base_url);
  if (!/^\/v1\/[a-zA-Z0-9/._:%-]+$/.test(path) || path.includes("..") ||
    (network !== "mainnet" && network !== "testnet")) {
    throw new TypeError("Invalid fixed Explorer API path or network");
  }
  const timeout = config.timeout_ms ?? DEFAULT_TIMEOUT;
  const budget = config.max_response_bytes ?? MAX_BYTES;
  if (!Number.isSafeInteger(timeout) || timeout < 100 || timeout > 60_000 ||
    !Number.isSafeInteger(budget) || budget < 1024 || budget > MAX_BYTES) {
    throw new TypeError("Invalid Explorer transport bounds");
  }
  const endpoint = new URL(path, base);
  if (query && postBody !== undefined) throw new TypeError("Explorer GET query cannot accompany POST body");
  if (query?.resultId !== undefined) {
    if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(query.resultId)) {
      throw new TypeError("Invalid Explorer resultId query");
    }
    endpoint.searchParams.set("resultId", query.resultId.toLowerCase());
  }
  if (postBody === undefined) endpoint.searchParams.set("network", network);
  const method = postBody === undefined ? "GET" : "POST";
  try {
    const response = await (config.fetch_impl ?? fetch)(endpoint.toString(), {
      method,
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        ...(postBody === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(postBody === undefined ? {} : { body: JSON.stringify(postBody) }),
      signal: AbortSignal.timeout(timeout),
    });
    if (response.status === 404) return { status: "not_found", reason_code: "EXPLORER_NOT_FOUND", body: null };
    if (!response.ok) return { status: "unavailable", reason_code: "EXPLORER_HTTP_UNAVAILABLE", body: null };
    const declaredNetwork = response.headers.get("x-hedera-network");
    if (declaredNetwork && declaredNetwork !== network) {
      return { status: "invalid", reason_code: "EXPLORER_NETWORK_MISMATCH", body: null };
    }
    const declaredSize = response.headers.get("content-length");
    if (declaredSize && Number(declaredSize) > budget) {
      return { status: "invalid", reason_code: "EXPLORER_RESPONSE_TOO_LARGE", body: null };
    }
    if (!response.body) return { status: "invalid", reason_code: "EXPLORER_EMPTY_RESPONSE", body: null };
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        size += next.value.byteLength;
        if (size > budget) {
          await reader.cancel().catch(() => undefined);
          return { status: "invalid", reason_code: "EXPLORER_RESPONSE_TOO_LARGE", body: null };
        }
        chunks.push(next.value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      return { status: "invalid", reason_code: "EXPLORER_RESPONSE_INVALID", body: null };
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { status: "invalid", reason_code: "EXPLORER_RESPONSE_INVALID", body: null };
    }
    return { status: "ok", reason_code: null, body: parsed };
  } catch {
    return { status: "unavailable", reason_code: "EXPLORER_REQUEST_UNAVAILABLE", body: null };
  }
}
