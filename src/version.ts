import pkg from "../package.json" with { type: "json" };

// VERSION is read from package.json at build time (bundled by `bun build`),
// falling back to a hardcoded default if the field is somehow absent.
export const VERSION: string =
  (pkg as { version?: string }).version ?? "0.1.0";
