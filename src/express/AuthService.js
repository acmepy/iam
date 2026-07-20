import { createSessionId, ensureAdapter, now, publicSession, publicUser } from "../core/utils.js";
import {
  AuthError,
  AuthRequiredError,
  SessionRequiredError,
  SessionInactiveError,
} from "../core/errors.js";

/**
 * Server-side authentication service for users and sessions.
 */
export class Auth {
  /**
   * @param {{ adapter: import("../types.js").Adapter, rbac?: import("../core/RBAC.js").RBAC }} options
   */
  constructor({ adapter, rbac } = {}) {
    ensureAdapter(adapter);
    this.adapter = adapter;
    this.rbac = rbac;
  }

  /**
   * Validate credentials and create a public session.
   *
   * @param {{ username?: string, password?: string, options?: import("../types.js").Dict }} credentials
   * @returns {Promise<import("../types.js").PublicSession>}
   */
  async login({ username, password, options = {} } = {}) {
    if (!username || password === undefined) {
      throw new AuthRequiredError();
    }

    const user = await this.adapter.findUserByUsername(username);
    await this.validateUser(user);
    await this.validatePassword(user, password);

    const session = await this.createSession({
      userId: user.id,
      options
    });

    return publicSession(session, user);
  }

  /**
   * Deactivate an existing session.
   *
   * @param {import("../types.js").Id} sessionId
   * @returns {Promise<import("../types.js").SessionData | null>}
   */
  async logout(sessionId) {
    if (!sessionId) {
      throw new SessionRequiredError();
    }

    return this.adapter.deactivateSession(sessionId);
  }

  /**
   * Load and validate an active public session.
   *
   * @param {import("../types.js").Id} sessionId
   * @returns {Promise<import("../types.js").PublicSession>}
   */
  async getSession(sessionId) {
    if (!sessionId) {
      throw new SessionRequiredError();
    }

    const session = await this.adapter.findSessionById(sessionId);

    if (!session) {
      throw new SessionRequiredError();
    }

    if (!session.active) {
      throw new SessionInactiveError();
    }

    const user = await this.adapter.findUserById(session.userId);
    await this.validateUser(user);

    return publicSession(session, user);
  }

  async validateUser(user) {
    if (!user) {
      throw new AuthError();
    }

    if (user.active === false) {
      throw new AuthError("Usuario inactivo");
    }
  }

  async validatePassword(user, password) {
    if (typeof this.adapter.verifyPassword === "function") {
      const valid = await this.adapter.verifyPassword(user, password);
      if (!valid) {
        throw new AuthError();
      }
      return;
    }

    if (user.password !== password) {
      throw new AuthError();
    }
  }

  /**
   * Persist a session through the configured adapter.
   *
   * @param {{ userId?: import("../types.js").Id, token?: string | null, options?: import("../types.js").Dict }} values
   * @returns {Promise<import("../types.js").SessionData>}
   */
  async createSession({ userId, token = null, options = {} } = {}) {
    const date = now();

    return this.adapter.createSession({
      id: createSessionId(),
      userId,
      token,
      options,
      active: true,
      createdAt: date,
      updatedAt: date
    });
  }

  /**
   * Build a public session without saving it.
   *
   * @param {import("../types.js").UserData} user
   * @param {import("../types.js").Dict} options
   * @returns {Promise<import("../types.js").PublicSession>}
   */
  async createTemporarySession(user, options = {}) {
    await this.validateUser(user);

    return {
      id: null,
      user: publicUser(user),
      options
    };
  }
}
