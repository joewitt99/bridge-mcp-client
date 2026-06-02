import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { generatePkce } from "../src/oauth/authcode.ts";

describe("generatePkce", () => {
  test("challenge == base64url(sha256(verifier))", () => {
    const { verifier, challenge } = generatePkce();
    const expected = createHash("sha256").update(verifier).digest("base64url");
    expect(challenge).toBe(expected);
  });

  test("verifier length is within [43,128]", () => {
    const { verifier } = generatePkce();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(verifier.length).toBeLessThanOrEqual(128);
  });

  test("verifier and challenge are base64url (no padding)", () => {
    const { verifier, challenge } = generatePkce();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test("two verifiers differ", () => {
    expect(generatePkce().verifier).not.toBe(generatePkce().verifier);
  });
});
