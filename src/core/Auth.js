import { createSessionId, ensureAdapter, now, publicSession, publicUser } from "./utils.js";
import {
  AuthError,
  AuthRequiredError,
  SessionRequiredError,
  SessionInactiveError,
} from "./errors.js";

export class Auth {
  constructor({ adapter, rbac } = {}) {
    ensureAdapter(adapter);
    this.adapter = adapter;
    this.rbac = rbac;
  }

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

  async logout(sessionId) {
    if (!sessionId) {
      throw new SessionRequiredError();
    }

    return this.adapter.deactivateSession(sessionId);
  }

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

  async createTemporarySession(user, options = {}) {
    await this.validateUser(user);

    return {
      id: null,
      user: publicUser(user),
      options
    };
  }
}
