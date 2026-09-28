import { createHash, randomBytes, randomUUID } from "node:crypto";
import { AdapterError, AuthError, NotFoundError, TokenInvalidError, ValidationError } from "../core/errors.js";
import { publicUser } from "../core/utils.js";

function requireMethods(adapter, ...methods) {
  for (const method of methods) {
    if (typeof adapter?.[method] !== "function") throw new AdapterError(`Adapter requiere ${method}`);
  }
}

function bodyFields(body, allowed) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new ValidationError("Cuerpo requerido");
  if (Object.keys(body).some(key => !allowed.includes(key))) throw new ValidationError("Campo no permitido");
}

function passwordValue(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 255) throw new ValidationError("Contrasena requerida (maximo 255 caracteres)");
  return value;
}

function profileValues(body, required = false) {
  const values = {};
  for (const field of ["name", "email"]) {
    if (required || Object.hasOwn(body, field)) {
      if (typeof body[field] !== "string" || !body[field].trim() || body[field].trim().length > 150) throw new ValidationError(`${field} requerido (maximo 150 caracteres)`);
      values[field] = body[field].trim();
    }
  }
  if (values.email !== undefined && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email)) throw new ValidationError("Email invalido");
  return values;
}

export async function register(adapter, body) {
  requireMethods(adapter, "createUser");
  bodyFields(body, ["name", "email", "password"]);
  const values = profileValues(body, true);
  const password = passwordValue(body.password);
  return publicUser(await adapter.createUser({ id: randomUUID(), ...values, password, active: true, options: {} }));
}

export async function updateProfile(adapter, userId, body) {
  requireMethods(adapter, "updateUser");
  bodyFields(body, ["name", "email"]);
  const values = profileValues(body);
  if (!Object.keys(values).length) throw new ValidationError("Indique name o email");
  const user = await adapter.updateUser(userId, values);
  if (!user) throw new NotFoundError();
  return publicUser(user);
}

export async function changePassword(adapter, userId, body) {
  requireMethods(adapter, "changePassword");
  bodyFields(body, ["currentPassword", "password"]);
  const currentPassword = passwordValue(body.currentPassword);
  const password = passwordValue(body.password);
  const user = await adapter.findUserById(userId);
  if (!user || user.active === false) throw new AuthError();
  const valid = typeof adapter.verifyPassword === "function"
    ? await adapter.verifyPassword(user, currentPassword)
    : user.password === currentPassword;
  if (!valid) throw new AuthError();
  if (!await adapter.changePassword(userId, user.password, password)) throw new AuthError();
}

function tokenHash(token) {
  return createHash("sha256").update(token).digest("hex");
}

/** Server-only: the caller must authorize recovery for the exact userId. */
export async function createPasswordReset({ adapter, userId, resetUrl, expiresIn = 1800 } = {}) {
  requireMethods(adapter, "findUserById", "createPasswordReset");
  if (!Number.isSafeInteger(expiresIn) || expiresIn <= 0) throw new ValidationError("expiresIn debe ser segundos positivos");
  let url;
  try { url = new URL(resetUrl); } catch { throw new ValidationError("resetUrl debe ser una URL absoluta"); }
  if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) throw new ValidationError("resetUrl invalida");
  if (!await adapter.findUserById(userId)) throw new NotFoundError();
  const token = randomBytes(32).toString("base64url");
  const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;
  if (!Number.isSafeInteger(expiresAt)) throw new ValidationError("expiresIn fuera de rango");
  await adapter.createPasswordReset({ id: tokenHash(token), userId, expiresAt });
  url.searchParams.set("token", token);
  return { url: url.href, expiresAt };
}

export async function resetPassword(adapter, body) {
  requireMethods(adapter, "resetPassword");
  bodyFields(body, ["token", "password"]);
  const password = passwordValue(body.password);
  if (typeof body.token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(body.token)) throw new TokenInvalidError();
  if (!await adapter.resetPassword(tokenHash(body.token), password, Math.floor(Date.now() / 1000))) throw new TokenInvalidError();
}
