class RbacError extends Error {
  constructor(message, status = 400, code = "RBAC_ERROR", errors = {}, stack) {
    super(message);

    this.name = this.constructor.name;
    this.status = status;
    this.code = code;
    this.errors = errors;
    this.isOperational = true;
    if (stack) this.stack = stack;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

const defaultState = {
  baseUrl: "",
  storageKey: "iam.session",
  storage: globalThis.localStorage
};

let current = load(defaultState);

/**
 * Browser auth client that stores the current session locally.
 */
const auth = {
  /**
   * @param {import("../types.js").BrowserAuthOptions} options
   * @returns {typeof auth}
   */
  configure(options = {}) {
    Object.assign(defaultState, options);
    current = load(defaultState);
    return this;
  },

  /**
   * @param {import("../types.js").BrowserCredentials} credentials
   * @returns {Promise<import("../types.js").PublicSession>}
   */
  async login(credentials = {}) {
    const session = credentials.token
      ? await loginWithToken(credentials.token)
      : await loginWithPassword(credentials);

    current = session;
    save(defaultState, session);
    return session;
  },

  async register(values) {
    return request("/register", { method: "POST", body: JSON.stringify(values) });
  },

  async updateProfile(values) {
    const user = await request("/me", { method: "PATCH", headers: sessionHeaders(), body: JSON.stringify(values) });
    current = { ...current, user };
    save(defaultState, current);
    return user;
  },

  async updateUserOptions(options) {
    const user = await request("/me/options", { method: "PATCH", headers: sessionHeaders(), body: JSON.stringify({ options }) });
    current = { ...current, user };
    save(defaultState, current);
    return user;
  },

  async updateSessionOptions(options) {
    const session = await request("/session/options", { method: "PATCH", headers: sessionHeaders(), body: JSON.stringify({ options }) });
    current = { ...current, ...session };
    save(defaultState, current);
    return current;
  },

  async setUserTenant(tenantId) {
    const user = await request("/me/tenant", { method: "PATCH", headers: sessionHeaders(), body: JSON.stringify({ tenantId }) });
    current = { ...current, user };
    save(defaultState, current);
    return user;
  },

  async setSessionTenant(tenantId) {
    const session = await request("/session/tenant", { method: "PATCH", headers: sessionHeaders(), body: JSON.stringify({ tenantId }) });
    current = { ...current, ...session };
    save(defaultState, current);
    return current;
  },

  async getTenants() {
    return request("/me/tenants", { headers: sessionHeaders() });
  },

  async changePassword(currentPassword, password) {
    await request("/me/password", { method: "POST", headers: sessionHeaders(), body: JSON.stringify({ currentPassword, password }) });
    current = null;
    remove(defaultState);
  },

  async resetPassword(token, password) {
    await request("/reset-password", { method: "POST", body: JSON.stringify({ token, password }) });
    current = null;
    remove(defaultState);
  },

  /**
   * @returns {Promise<void>}
   */
  async logout() {
    if (current?.token) {
      await request("/logout", {
        method: "POST",
        headers: sessionHeaders()
      });
    }

    current = null;
    remove(defaultState);
  },

  /**
   * @returns {import("../types.js").PublicSession | null}
   */
  getSession() {
    return current;
  }
};

async function loginWithPassword({ username, password, options = {} }) {
  return request("/login", {
    method: "POST",
    body: JSON.stringify({ username, password, options })
  });
}

async function loginWithToken(token) {
  const session = await request("/session", {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
  return { ...session, token };
}

function sessionHeaders() {
  if (!current?.token) throw new RbacError("Sesion requerida", 401);
  return { Authorization: `Bearer ${current.token}` };
}

async function request(path, init = {}) {
  const response = await fetch(`${defaultState.baseUrl}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init.headers ?? {})
    }
  });

  const result = await response.json();
  if (!response.ok) {
    throw new RbacError(result.message || `Solicitud fallida con estado ${response.status}`, response.status, result.code, result.errors);
  }
  return result.data;
}

function load({ storage, storageKey }) {
  if (!storage) {
    return null;
  }

  const value = storage.getItem(storageKey);
  return value ? JSON.parse(value) : null;
}

function save({ storage, storageKey }, session) {
  if (storage) {
    storage.setItem(storageKey, JSON.stringify(session));
  }
}

function remove({ storage, storageKey }) {
  if (storage) {
    storage.removeItem(storageKey);
  }
}

/**
 * Check whether the current browser session has a permission.
 *
 * @param {string} permission
 * @returns {Promise<boolean>}
 */
async function can(permission) {
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

export { auth, can };
