import { Auth } from "./AuthService.js";

export { Auth };
export { auth } from "./auth.js";
export { can } from "./can.js";
export { signJwt, verifyJwt } from "./jwt.js";

/**
 * Convenience factory for the server-side Auth service.
 *
 * @param {import("../types.js").Adapter} adapter
 * @returns {Auth}
 */
export function createAuth(adapter) {
  return new Auth({ adapter });
}
