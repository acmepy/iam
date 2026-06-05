import { createHmac, timingSafeEqual } from "node:crypto";
import { TokenInvalidError, TokenRequiredError } from "../core/errors.js";

export function signJwt(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const body = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));
  const signature = createSignature(body, secret);
  return `${body}.${signature}`;
}

export function verifyJwt(token, secret) {
  if (!token) {
    throw new TokenRequiredError();
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new TokenInvalidError();
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const body = `${encodedHeader}.${encodedPayload}`;
  const expected = createSignature(body, secret);

  if (!safeEqual(signature, expected)) {
    throw new TokenInvalidError();
  }

  const header = parseJson(encodedHeader);

  if (header.alg !== "HS256") {
    throw new TokenInvalidError();
  }

  return parseJson(encodedPayload);
}

function createSignature(value, secret) {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function fromBase64url(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

function parseJson(value) {
  try {
    return JSON.parse(fromBase64url(value));
  } catch {
    throw new TokenInvalidError();
  }
}
