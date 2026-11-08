import type { HederaNetwork } from "../contracts/verification.js";

const MAX_AUTHORIZATION_BYTES = 8 * 1024;
const MAX_STATIC_TOKEN_BYTES = 4 * 1024;
const AUTHORIZATION = /^[A-Za-z][A-Za-z0-9+.-]* [\x21-\x7e]+$/;

export type CoreAuthorizationRequestV1 = Readonly<{
  origin: string;
  path: "/v1/hcs/verify-decrypt";
  method: "POST";
  network: HederaNetwork;
}>;

export type CoreAuthorizationMaterialV1 = Readonly<{
  authorization: string;
}>;

/**
 * Supplies authorization for one explicitly scoped Core request.
 * Providers cannot alter the destination, request body, or verification intent.
 */
export type AuthProviderV1 = Readonly<{
  authorize(
    request: CoreAuthorizationRequestV1,
  ): CoreAuthorizationMaterialV1 | Promise<CoreAuthorizationMaterialV1>;
}>;

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

export class AuthProviderContractErrorV1 extends TypeError {
  constructor(message = "AuthProvider returned invalid authorization material") {
    super(message);
    this.name = "AuthProviderContractErrorV1";
  }
}

function authorization(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value ||
    utf8Bytes(value) > MAX_AUTHORIZATION_BYTES || !AUTHORIZATION.test(value)) {
    throw new AuthProviderContractErrorV1();
  }
  return value;
}

/** Convenience provider for the current Core bearer-token/API-key contract. */
export function createStaticBearerAuthProviderV1(token: string): AuthProviderV1 {
  if (typeof token !== "string" || token.length === 0 || token.trim() !== token ||
    utf8Bytes(token) > MAX_STATIC_TOKEN_BYTES || !/^[\x21-\x7e]+$/.test(token)) {
    throw new TypeError("Bearer token must be a bounded printable ASCII token");
  }

  return Object.freeze({
    authorize: () => Object.freeze({ authorization: `Bearer ${token}` }),
  });
}

export async function resolveCoreAuthorizationV1(
  provider: AuthProviderV1,
  request: CoreAuthorizationRequestV1,
): Promise<CoreAuthorizationMaterialV1> {
  if (!provider || typeof provider.authorize !== "function") {
    throw new AuthProviderContractErrorV1("AuthProviderV1 with authorize() is required");
  }
  const material = await provider.authorize(Object.freeze({ ...request }));
  if (!material || typeof material !== "object" || Array.isArray(material)) {
    throw new AuthProviderContractErrorV1();
  }
  return Object.freeze({ authorization: authorization(material.authorization) });
}
