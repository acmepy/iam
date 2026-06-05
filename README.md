# iam

Small IAM authentication, authorization, and session library for JavaScript.

`iam` provides a lightweight core for login/logout, session validation, role-based access control, browser helpers, Express middleware, and pluggable persistence adapters.

## Installation

```sh
npm install iam
```

## Quick Start

```js
import { createAuth, MemoryAdapter, RBAC } from "iam";

const adapter = new MemoryAdapter({
  users: [
    {
      id: "admin",
      password: "1234",
      name: "Administrador",
      email: "admin@app.com",
      options: {},
      active: true
    }
  ],
  roles: [{ id: 1, role: "admin", active: true }],
  permissions: [{ id: 1, permission: "users.list", active: true }],
  userRoles: [{ id: 1, userId: "admin", roleId: 1, active: true }],
  rolePermissions: [{ id: 1, roleId: 1, permissionId: 1, active: true }]
});

const auth = createAuth(adapter);

const session = await auth.login({
  username: "admin",
  password: "1234",
  options: { empresa: 1, sucursal: 2 }
});

console.log(session.user.id); // admin

const rbac = new RBAC({ adapter });
console.log(await rbac.can("admin", "users.list")); // true
```

## Core API

### Auth

```js
import { Auth, MemoryAdapter } from "iam";

const auth = new Auth({ adapter: new MemoryAdapter() });
```

Main methods:

- `login({ username, password, options })`: validates credentials and creates a public session.
- `logout(sessionId)`: deactivates a session.
- `getSession(sessionId)`: returns an active public session.
- `createSession({ userId, token, options })`: creates a session directly.
- `createTemporarySession(user, options)`: creates a non-persisted public session shape.

### RBAC

```js
import { RBAC } from "iam";

const rbac = new RBAC({ adapter });

await rbac.hasRole("admin", "admin");
await rbac.can("admin", "users.list");
```

## Express Middleware

```js
import express from "express";
import { MemoryAdapter } from "iam/adapters";
import { auth, can, signJwt } from "iam/express";

const app = express();
const adapter = new MemoryAdapter();
const secret = "replace-with-a-secure-secret";

app.get(
  "/users",
  auth({ strategy: "jwt", secret, adapter }),
  can("users.list"),
  (req, res) => {
    res.json({ session: req.session });
  }
);

const token = await signJwt({ sessionId: "session-id" }, secret);
```

The `auth` middleware supports:

- JWT bearer tokens with `auth({ strategy: "jwt", secret, adapter })`.
- Basic auth with `auth({ strategy: "basic", adapter })`.
- Automatic strategy detection with `auth({ adapter, secret })`.

## Adapters

Available adapters:

- `MemoryAdapter`
- `LocalStorageAdapter`
- `IndexedDBAdapter`
- `SequelizeAdapter`

Adapters are responsible for user lookup, password verification, session persistence, role lookup, and permission lookup.

## Exports

```js
import { Auth, RBAC, MemoryAdapter, createAuth } from "iam";
import { MemoryAdapter } from "iam/adapters";
import { auth, can, signJwt, verifyJwt } from "iam/express";
import { auth, can } from "iam/browser";
```

## Testing

```sh
npm test
```

## License

MIT
