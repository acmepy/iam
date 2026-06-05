import { AdapterError } from "./errors.js";

export function now() {
  return new Date();
}

export function publicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    options: user.options ?? {}
  };
}

export function publicSession(session, user) {
  return {
    id: session.id,
    user: publicUser(user),
    options: session.options ?? {}
  };
}

export function createSessionId() {
  const time = Date.now().toString(36).toUpperCase().padStart(10, "0");
  const random = Math.random().toString(36).slice(2, 18).toUpperCase().padEnd(16, "0");
  return `${time}${random}`.slice(0, 26);
}

export function ensureAdapter(adapter) {
  if (!adapter) {
    throw new AdapterError("Adapter requerido");
  }
}
