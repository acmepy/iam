import { auth } from "./auth.js";

export async function can(permission) {
  const session = auth.getSession();

  if (!session) {
    return false;
  }

  if (Array.isArray(session.permissions)) {
    return session.permissions.includes(permission);
  }

  const response = await fetch(`/can/${encodeURIComponent(permission)}`, {
    headers: session.token ? { Authorization: `Bearer ${session.token}` } : {}
  });

  if (!response.ok) {
    return false;
  }

  const result = await response.json();
  return result.allowed === true;
}
