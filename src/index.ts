import { randomBytes, webcrypto } from "crypto";
import * as jose from "jose";

export class JWT {
  #accessKey: webcrypto.CryptoKeyPair;
  #refreshKey: webcrypto.CryptoKeyPair;
  #issuer: string;
  #subject: string;
  #audience: string;
  #edDSA = "EdDSA";

  constructor(
    accessKey: webcrypto.CryptoKeyPair,
    refreshKey: webcrypto.CryptoKeyPair,
    issuer: string,
    subject: string,
    audience: string,
  ) {
    this.#accessKey = accessKey;
    this.#refreshKey = refreshKey;
    this.#issuer = issuer;
    this.#subject = subject;
    this.#audience = audience;
  }

  async Sign(payload?: object): Promise<[string, string]> {
    const accessBuffer = randomBytes(32);
    const accessRandId = accessBuffer.toString("hex");

    const accessClaims: jose.JWTPayload = {
      iss: this.#issuer,
      sub: this.#subject,
      aud: this.#audience,
      exp: Math.floor((Date.now() + 1 * 60 * 60 * 1000) / 1000), // One hour from now
      nbf: Math.floor(Date.now() / 1000),
      iat: Math.floor(Date.now() / 1000),
      jti: accessRandId,
      ...payload,
    };

    const accessToken = await new jose.SignJWT(accessClaims)
      .setProtectedHeader({ alg: this.#edDSA })
      .sign(this.#accessKey.privateKey);

    const refreshBuffer = randomBytes(32);
    const refreshRandId = refreshBuffer.toString("hex");

    const refreshClaims: jose.JWTPayload = {
      iss: this.#issuer,
      sub: this.#subject,
      aud: this.#audience,
      exp: Math.floor((Date.now() + 24 * 60 * 60 * 1000) / 1000), // 24 hour from now
      nbf: Math.floor((Date.now() + 59 * 60 * 1000) / 1000), // 59 minute
      iat: Math.floor(Date.now() / 1000),
      jti: refreshRandId,
      ...payload,
    };

    const refreshToken = await new jose.SignJWT(refreshClaims)
      .setProtectedHeader({ alg: this.#edDSA })
      .sign(this.#refreshKey.privateKey);

    return [accessToken, refreshToken];
  }
}
