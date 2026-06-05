import { Auth } from "./AuthService.js";

export { Auth };
export { auth } from "./auth.js";
export { can } from "./can.js";
export { signJwt, verifyJwt } from "./jwt.js";

export function createAuth(adapter) {
  return new Auth({ adapter });
}
