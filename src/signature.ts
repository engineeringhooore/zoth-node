import type { webcrypto } from "crypto";

const { subtle } = globalThis.crypto;

export class ED25519 {
  constructor() {}

  async GenerateKey(): Promise<webcrypto.CryptoKeyPair> {
    const cryptoKeyPair = (await subtle.generateKey("Ed25519", false, [
      "sign",
    ])) as webcrypto.CryptoKeyPair;
    return cryptoKeyPair;
  }
}
