import { describe, expect, it } from "vitest";
import {
  buildHcs14DidUaidV1, parseHcs14DidUaidV1, verifyHcs14DidBindingV1,
} from "../../src/standards/hcs/hcs14V1.js";
import {
  parseHcs11AccountMemoV1, parseHcs11AiAgentProfileV1, verifyHcs11AiAgentProfileV1,
} from "../../src/standards/hcs/hcs11V1.js";

const BASE_DID = "did:web:agents.veraanchor.ai";
const SUFFIXED_DID = `${BASE_DID}?version=1`;
const NATIVE = "hedera:testnet:0.0.123456";
const UAID = `uaid:did:agents.veraanchor.ai;uid=sage;registry=self;proto=hcs-26;nativeId=${NATIVE}`;
const SRC = "zFrWvUrxPsHrJVpTfYyQ6qu2m3NsjcigsLcnT8wo7FiSTRTeDoEu6";
const SOURCE_PROFILE_UAID = "uaid:did:sage;uid=sage;registry=self;proto=hcs-26;nativeId=hedera:testnet:0.0.123456";
const SHA256 = "f461c50805bdfadb1d2966c04a62e273cdb108e84201448323ab826c982f8f3e";
const profile = () => ({
  version: "1.1", type: 1, display_name: "SAGE", uaid: SOURCE_PROFILE_UAID,
  alias: "sage", bio: "Vera Anchor SAGE compute agent", profileImage: "hcs://1/0.0.7001",
  properties: { network: "testnet", service: "sage", nested: { z: 2, a: 1 } },
  aiAgent: { type: 1, capabilities: [17, 0, 7], model: "vera-anchor-sage", creator: "Vera Anchor" },
});
const input = (overrides: Record<string, unknown> = {}) => JSON.stringify({ ...profile(), ...overrides });

describe("pinned HCS-14 uaid:did offline checks", () => {
  it("parses canonical UAID and freezes parsed parameters", () => {
    const value = parseHcs14DidUaidV1(UAID);
    expect(value).toMatchObject({ target: "did", id: "agents.veraanchor.ai",
      params: { uid: "sage", proto: "hcs-26", nativeId: NATIVE } });
    expect(Object.isFrozen(value)).toBe(true);
    expect(Object.isFrozen(value.params)).toBe(true);
  });
  it("matches unsanitized and sanitized frozen SAGE vectors", () => {
    const args = { uid: "sage", registry: "self", proto: "hcs-26", native_id: NATIVE };
    expect(buildHcs14DidUaidV1({ ...args, base_did: BASE_DID }).uaid).toBe(UAID);
    expect(buildHcs14DidUaidV1({ ...args, base_did: SUFFIXED_DID }).uaid).toBe(`${UAID};src=${SRC}`);
    expect(verifyHcs14DidBindingV1({ uaid: `${UAID};src=${SRC}`, base_did: SUFFIXED_DID }).status).toBe("pass");
  });
  it("fails binding for wrong DID, missing src, altered src, and unexpected src", () => {
    expect(verifyHcs14DidBindingV1({ uaid: UAID, base_did: "did:web:other.example" }).reason_code)
      .toBe("HCS14_DID_BINDING_MISMATCH");
    expect(verifyHcs14DidBindingV1({ uaid: UAID, base_did: SUFFIXED_DID }).reason_code)
      .toBe("HCS14_SRC_REQUIRED");
    expect(verifyHcs14DidBindingV1({ uaid: `${UAID};src=z0`, base_did: SUFFIXED_DID }).reason_code)
      .toBe("HCS14_SRC_INVALID");
    expect(verifyHcs14DidBindingV1({ uaid: `${UAID};src=z2`, base_did: BASE_DID }).reason_code)
      .toBe("HCS14_SRC_UNEXPECTED");
  });
  it("rejects AID target, duplicate/unknown params, reordered params, and controls", () => {
    expect(() => parseHcs14DidUaidV1(UAID.replace("uaid:did:", "uaid:aid:"))).toThrow("HCS14_TARGET_UNSUPPORTED");
    expect(() => parseHcs14DidUaidV1(`${UAID};uid=again`)).toThrow("HCS14_PARAMETER_INVALID");
    expect(() => parseHcs14DidUaidV1(`${UAID};test=one`)).toThrow("HCS14_PARAMETER_INVALID");
    expect(() => parseHcs14DidUaidV1(UAID.replace("uid=sage;registry=self", "registry=self;uid=sage")))
      .toThrow("HCS14_PARAMETER_ORDER_INVALID");
    expect(() => parseHcs14DidUaidV1(UAID.replace("uid=sage", "uid=bad\nname")))
      .toThrow("HCS14_FIELD_INVALID");
  });
});

describe("pinned HCS-11 AI agent offline checks", () => {
  it("parses supported HCS-1/HCS-2 account memo references without asserting account ownership", () => {
    expect(parseHcs11AccountMemoV1("hcs-11:hcs://1/0.0.1234")).toMatchObject({ protocol: "hcs-1", topic_id: "0.0.1234" });
    expect(parseHcs11AccountMemoV1("hcs-11:hcs://2/0.0.1234")).toMatchObject({ protocol: "hcs-2", topic_id: "0.0.1234" });
    expect(() => parseHcs11AccountMemoV1("hcs-11:https://elsewhere/agent")).toThrow("HCS11_PROFILE_REF_INVALID");
  });
  it("recomputes the independent frozen canonical SHA-256 vector", () => {
    const result = verifyHcs11AiAgentProfileV1({ profile: input(), expected_sha256: SHA256 });
    expect(result).toMatchObject({ status: "pass", reason_code: null, sha256: SHA256,
      profile: { aiAgent: { capabilities: [0, 7, 17] } }, memo_reference_match: "not_checked" });
  });
  it("recomputes same SHA-256 for reordered profile properties and capabilities", () => {
    const alternate = input({ properties: { nested: { a: 1, z: 2 }, service: "sage", network: "testnet" },
      aiAgent: { capabilities: [0, 7, 17], creator: "Vera Anchor", model: "vera-anchor-sage", type: 1 } });
    expect(verifyHcs11AiAgentProfileV1({ profile: alternate, expected_sha256: SHA256 }).status).toBe("pass");
  });
  it("detects externally expected checksum and UAID substitutions", () => {
    expect(verifyHcs11AiAgentProfileV1({ profile: input(), expected_sha256: "0".repeat(64) }).reason_code)
      .toBe("HCS11_CHECKSUM_MISMATCH");
    expect(verifyHcs11AiAgentProfileV1({ profile: input(), expected_uaid: UAID }).reason_code)
      .toBe("HCS11_UAID_MISMATCH");
  });
  it("compares memo references only against independently supplied expectations", () => {
    const profileInput = input();
    expect(verifyHcs11AiAgentProfileV1({ profile: profileInput, account_memo: "hcs-11:hcs://1/0.0.1234" }))
      .toMatchObject({ status: "pass", memo_reference_match: "not_checked" });
    expect(verifyHcs11AiAgentProfileV1({ profile: profileInput, account_memo: "hcs-11:hcs://1/0.0.1234",
      expected_profile_reference: "hcs://1/0.0.1234" })).toMatchObject({ status: "pass", memo_reference_match: "match" });
    expect(verifyHcs11AiAgentProfileV1({ profile: profileInput, account_memo: "hcs-11:hcs://1/0.0.1234",
      expected_profile_reference: "hcs://1/0.0.9999" })).toMatchObject({ status: "fail", memo_reference_match: "mismatch" });
  });
  it("rejects unsupported profile type, capabilities and unrecognized field", () => {
    expect(verifyHcs11AiAgentProfileV1({ profile: input({ type: 2 }) }).reason_code)
      .toBe("HCS11_PROFILE_TYPE_UNSUPPORTED");
    expect(verifyHcs11AiAgentProfileV1({ profile: input({ aiAgent: { type: 1, capabilities: [7, 7], model: "sage" } }) }).reason_code)
      .toBe("HCS11_CAPABILITIES_INVALID");
    expect(verifyHcs11AiAgentProfileV1({ profile: input({ inboundTopicId: "0.0.1234" }) }).reason_code)
      .toBe("HCS11_FIELD_UNSUPPORTED");
  });
  it("rejects ambiguous JSON duplicate keys including escaped aliases", () => {
    const duplicate = input().replace('"version":"1.1"', '"version":"1.1","version":"1.2"');
    expect(verifyHcs11AiAgentProfileV1({ profile: duplicate }).reason_code).toBe("HCS11_PROFILE_JSON_INVALID");
    const escaped = input().replace('"version":"1.1"', '"version":"1.1","vers\\u0069on":"1.2"');
    expect(verifyHcs11AiAgentProfileV1({ profile: escaped }).reason_code).toBe("HCS11_PROFILE_JSON_INVALID");
  });
  it("rejects malformed UTF-8 and extra-large supplied content", () => {
    expect(verifyHcs11AiAgentProfileV1({ profile: Uint8Array.from([123, 255, 125]) }).reason_code)
      .toBe("HCS11_PROFILE_JSON_INVALID");
    expect(verifyHcs11AiAgentProfileV1({ profile: "x".repeat(128 * 1024 + 1) }).reason_code)
      .toBe("HCS11_PROFILE_TOO_LARGE");
  });
  it("treats a different standards version as unsupported, not verified", () => {
    expect(verifyHcs11AiAgentProfileV1({ profile: input({ version: "1.2" }) }))
      .toMatchObject({ status: "unsupported", reason_code: "HCS11_VERSION_UNSUPPORTED" });
  });
  it("keeps malformed properties from yielding a canonical checksum", () => {
    const p = parseHcs11AiAgentProfileV1(input());
    expect(p.aiAgent.capabilities).toEqual([0, 7, 17]);
    const modified = input().replace('"z":2', '"z":1e999');
    expect(verifyHcs11AiAgentProfileV1({ profile: modified }).reason_code).toBe("HCS11_CANONICALIZATION_FAILED");
  });
});
