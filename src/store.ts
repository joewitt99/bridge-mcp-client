// Encrypted-at-rest token store.
//
// Persists the OAuth token set to <BRIDGE_HOME>/tokens.json, sealed via
// src/crypto.ts (AES-256-GCM, chmod 600). Never log token material.
import { chmodSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureBridgeHome, openJson, sealJson, type Sealed } from "./crypto.ts";

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  /** Absolute expiry in epoch seconds. */
  expiresAt: number;
  scope: string;
  /** RFC 7638 thumbprint of the DPoP key the token is bound to. */
  jkt: string;
}

export class TokenStore {
  private readonly path: string;

  constructor(private readonly home: string) {
    this.path = join(home, "tokens.json");
  }

  /** Load the persisted token set, or null if none exists. */
  load(): TokenSet | null {
    if (!existsSync(this.path)) return null;
    const sealed = JSON.parse(readFileSync(this.path, "utf8")) as Sealed;
    return openJson<TokenSet>(this.home, sealed);
  }

  /** Persist the token set, encrypted, chmod 600. */
  save(set: TokenSet): void {
    ensureBridgeHome(this.home);
    const sealed = sealJson(this.home, set);
    writeFileSync(this.path, JSON.stringify(sealed), { mode: 0o600 });
    chmodSync(this.path, 0o600);
  }

  /** Remove the persisted token set. */
  clear(): void {
    if (existsSync(this.path)) rmSync(this.path, { force: true });
  }

  /** True if the set is expired (or within `skew` seconds of expiring). */
  isExpired(set: TokenSet, skew = 60): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= set.expiresAt - skew;
  }
}
