import { SignJWT, jwtVerify } from "jose";
import { TokenInvalidError, ValidationError } from "./errors.js";

const defaultExpiresIn = 365 * 24 * 60 * 60;

export async function signJwt(payload, secret, options = {}) {
  if (!secret) throw new ValidationError("Secret requerido para JWT");

  const jwt = new SignJWT(payload).setProtectedHeader({ alg: "HS256", typ: "JWT" });
  const expiresIn = normalizeExpiresIn(options.expiresIn);

  if (expiresIn) {
    const issuedAt = Math.floor(Date.now() / 1000);
    jwt.setIssuedAt(issuedAt).setExpirationTime(issuedAt + expiresIn);
  }

  return jwt.sign(createSecretKey(secret));
}

/**
 * Verifies an HS256 JWT and returns its verified payload.
 *
 * @param {string} token
 * @param {string} secret
 * @returns {Promise<import("jose").JWTPayload>}
 */
export async function verifyJwt(token, secret) {
  try {
    const { payload } = await jwtVerify(token, createSecretKey(secret), {algorithms: ["HS256"]});
    return payload;
  } catch {
    throw new TokenInvalidError();
  }
}

export function normalizeExpiresIn(expiresIn) {
  if (expiresIn === undefined || expiresIn === null) return defaultExpiresIn;

  if (typeof expiresIn === "number" && Number.isFinite(expiresIn) && expiresIn > 0) return Math.floor(expiresIn);

  if (typeof expiresIn === "string") {
    const match = expiresIn.trim().match(/^(\d+)\s*([smhd])?$/i);
    if (!match) throw new ValidationError("expiresIn JWT invalido");

    const value = Number(match[1]);
    const unit = match[2]?.toLowerCase() ?? "s";
    const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
    return value * multipliers[unit];
  }

  throw new ValidationError("expiresIn JWT invalido");
}

function createSecretKey(secret) {
  return new TextEncoder().encode(secret);
}

