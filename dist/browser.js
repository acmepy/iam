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

  /**
   * @returns {Promise<void>}
   */
  async logout() {
    if (current?.id) {
      await request("/logout", {
        method: "POST",
        body: JSON.stringify({ sessionId: current.id })
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
  return request("/session", {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
}

async function request(path, init = {}) {
  const response = await fetch(`${defaultState.baseUrl}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init.headers ?? {})
    }
  });

  if (!response.ok) {
    throw new RbacError(`Solicitud fallida con estado ${response.status}`, response.status);
  }

  return response.json();
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
