import { randomBytes, webcrypto } from "crypto";
import * as jose from "jose";

export type Alg =
  | "EdDSA"
  | "ES256"
  | "ES256K"
  | "ES384"
  | "ES512"
  | "HS256"
  | "HS384"
  | "HS512"
  | "PS256"
  | "PS384"
  | "PS512"
  | "RS256"
  | "RS384"
  | "RS512";

export class CompactJWS {
  #issuer: string;
  #audience: string | string[];
  #alg: Alg;

  constructor(alg: Alg, issuer: string, audience: string | string[]) {
    this.#alg = alg;
    this.#issuer = issuer;
    this.#audience = audience;
  }

  async Sign(
    accessPrivateKey: webcrypto.CryptoKey,
    refreshPrivateKey: webcrypto.CryptoKey,
    payload?: object,
  ): Promise<[string, string]> {
    const accessBuffer = randomBytes(32);
    const accessRandId = accessBuffer.toString("hex");

    const accessClaims: jose.JWTPayload = {
      iss: this.#issuer,
      aud: this.#audience,
      exp: Math.floor((Date.now() + 1 * 60 * 60 * 1000) / 1000), // One hour from now
      nbf: Math.floor(Date.now() / 1000),
      iat: Math.floor(Date.now() / 1000),
      jti: accessRandId,
      ...payload,
    };

    const accessToken = await new jose.SignJWT(accessClaims)
      .setProtectedHeader({ alg: this.#alg })
      .sign(accessPrivateKey);

    const refreshBuffer = randomBytes(32);
    const refreshRandId = refreshBuffer.toString("hex");

    const refreshClaims: jose.JWTPayload = {
      iss: this.#issuer,
      aud: this.#audience,
      exp: Math.floor((Date.now() + 24 * 60 * 60 * 1000) / 1000), // 24 hour from now
      nbf: Math.floor((Date.now() + 59 * 60 * 1000) / 1000), // 59 minute
      iat: Math.floor(Date.now() / 1000),
      jti: refreshRandId,
      ...payload,
    };

    const refreshToken = await new jose.SignJWT(refreshClaims)
      .setProtectedHeader({ alg: this.#alg })
      .sign(refreshPrivateKey);

    return [accessToken, refreshToken];
  }

  async VerifyAccessToken(
    token: string,
    accessPublicKey: webcrypto.CryptoKey,
  ): Promise<jose.JWTPayload> {
    const jwtResult = await jose.jwtVerify(token, accessPublicKey, {
      audience: this.#audience,
      currentDate: new Date(),
      issuer: this.#issuer,
    });

    const jwtPayload = jwtResult.payload;
    if (!jwtPayload.jti) {
      throw new Error("token claims invalid");
    }

    return jwtPayload;
  }

  async VerifyRefreshToken(
    token: string,
    refreshPublicKey: webcrypto.CryptoKey,
  ): Promise<jose.JWTPayload> {
    const jwtResult = await jose.jwtVerify(token, refreshPublicKey, {
      audience: this.#audience,
      currentDate: new Date(),
      issuer: this.#issuer,
    });

    const jwtPayload = jwtResult.payload;
    if (!jwtPayload.jti) {
      throw new Error("token claims invalid");
    }

    return jwtPayload;
  }
}

export class JWT extends CompactJWS {
  constructor(issuer: string, audience: string) {
    super("EdDSA", issuer, audience);
  }
}
