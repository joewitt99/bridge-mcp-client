import { test, expect, spyOn, beforeEach, afterEach } from "bun:test";
import { logger, redactToken, redactKey } from "../src/logger.ts";

let stderrSpy: ReturnType<typeof spyOn>;
let stdoutSpy: ReturnType<typeof spyOn>;

beforeEach(() => {
  stderrSpy = spyOn(process.stderr, "write").mockImplementation(() => true);
  stdoutSpy = spyOn(process.stdout, "write").mockImplementation(() => true);
});

afterEach(() => {
  stderrSpy.mockRestore();
  stdoutSpy.mockRestore();
  delete process.env.LOG_LEVEL;
});

test("writes a single valid JSON line to stderr", () => {
  logger.info("test.event", { foo: "bar" });
  expect(stderrSpy).toHaveBeenCalledTimes(1);
  const line = stderrSpy.mock.calls[0]![0] as string;
  expect(line.endsWith("\n")).toBe(true);
  const parsed = JSON.parse(line);
  expect(parsed.level).toBe("info");
  expect(parsed.event).toBe("test.event");
  expect(parsed.foo).toBe("bar");
  expect(typeof parsed.ts).toBe("string");
  expect(() => new Date(parsed.ts as string).toISOString()).not.toThrow();
});

test("never writes to stdout", () => {
  logger.info("a");
  logger.warn("b");
  logger.error("c");
  logger.debug("d");
  expect(stdoutSpy).not.toHaveBeenCalled();
});

test("withCorrelation injects correlation_id", () => {
  logger.withCorrelation("corr-123").info("with.corr");
  const line = stderrSpy.mock.calls[0]![0] as string;
  expect(JSON.parse(line).correlation_id).toBe("corr-123");
});

test("base logger omits correlation_id", () => {
  logger.info("no.corr");
  const line = stderrSpy.mock.calls[0]![0] as string;
  expect(JSON.parse(line).correlation_id).toBeUndefined();
});

test("LOG_LEVEL gates lower-severity events", () => {
  process.env.LOG_LEVEL = "warn";
  logger.info("dropped");
  logger.debug("also.dropped");
  expect(stderrSpy).not.toHaveBeenCalled();
  logger.warn("kept");
  logger.error("kept.too");
  expect(stderrSpy).toHaveBeenCalledTimes(2);
});

test("LOG_LEVEL=debug is verbose", () => {
  process.env.LOG_LEVEL = "debug";
  logger.debug("verbose");
  expect(stderrSpy).toHaveBeenCalledTimes(1);
});

test("redactToken excludes the raw token", () => {
  const token = "super-secret-token-value";
  const red = redactToken(token);
  expect(red).not.toContain(token);
  expect(red).toContain(`len=${token.length}`);
  expect(red).toMatch(/sha256=[0-9a-f]{12}/);
});

test("redactKey shows public metadata but not private params", () => {
  const jwk = { kty: "EC", crv: "P-256", x: "PUBX", y: "PUBY", d: "PRIVATE-D" };
  const red = redactKey(jwk);
  expect(red).not.toContain("PRIVATE-D");
  expect(red).toContain("kty=EC");
  expect(red).toContain("crv=P-256");
  expect(red).toMatch(/jkt=[A-Za-z0-9_-]+/);
});
