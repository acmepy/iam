import { SignJWT, jwtVerify } from "jose";
import { TokenInvalidError, TokenRequiredError } from "../core/errors.js";

export async function signJwt(payload, secret) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .sign(createSecretKey(secret));
}

export async function verifyJwt(token, secret) {
  if (!token) {
    throw new TokenRequiredError();
  }

  try {
    const { payload } = await jwtVerify(token, createSecretKey(secret), {
      algorithms: ["HS256"]
    });
    return payload;
  } catch {
    throw new TokenInvalidError();
  }
}

function createSecretKey(secret) {
  return new TextEncoder().encode(secret);
}
