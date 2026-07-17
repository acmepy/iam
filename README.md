# iam

IAM es una pequeña biblioteca para autenticación, autorización y gestión de sesiones en JavaScript.

`iam` ofrece controles de acceso basado en roles, helpers de autenticación para servidor, clientes para navegador, middleware para Express y adaptadores de persistencia enchufables.

## Instalación

```sh
npm install iam
```

## Inicio rápido

```js
import { MemoryAdapter, RBAC } from "iam";
import { createAuth } from "iam/express";

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

## API de autenticación del servidor

### Auth

```js
import { MemoryAdapter } from "iam";
import { Auth } from "iam/express";

const auth = new Auth({ adapter: new MemoryAdapter() });
```

Métodos principales:

- `login({ username, password, options })`: valida credenciales y crea una sesión pública.
- `logout(sessionId)`: desactiva una sesión.
- `getSession(sessionId)`: devuelve una sesión pública activa.
- `createSession({ userId, token, options })`: crea una sesión directamente.
- `createTemporarySession(user, options)`: crea una sesión temporal que no se persiste.

### RBAC

```js
import { RBAC } from "iam";

const rbac = new RBAC({ adapter });

await rbac.hasRole("admin", "admin");
await rbac.can("admin", "users.list");
```

## Middleware para Express

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

`auth` admite:

- Tokens bearer JWT con `auth({ strategy: "jwt", secret, adapter })`.
- Autenticación básica con `auth({ strategy: "basic", adapter })`.
- Detección automática de estrategia con `auth({ adapter, secret })`.

## Cliente para navegador

```js
import { auth, can } from "iam/browser";

auth.configure({
  baseUrl: "https://api.example.com",
  storageKey: "iam.session"
});

const session = await auth.login({
  username: "admin",
  password: "1234",
  options: { empresa: 1 }
});

console.log(session.user.id); // admin

if (await can("users.list")) {
  // Muestra o habilita la interfaz para listar usuarios.
}

await auth.logout();
```

El cliente del navegador espera que el servidor exponga:

- `POST /login` para login con usuario y contraseña.
- `POST /logout` para cerrar sesión.
- `GET /session` para login con token bearer.
- `GET /can/:permission` para verificar permisos cuando no están embebidos en la sesión.

## Adaptadores

Adaptadores disponibles:

- `MemoryAdapter`
- `LocalStorageAdapter`
- `IndexedDBAdapter`
- `SequelizeAdapter`
- `SeqAdapter`

Los adaptadores se encargan de la búsqueda de usuarios, verificación de contraseñas, persistencia de sesiones, búsqueda de roles y búsqueda de permisos.

### SeqAdapter

`SeqAdapter` permite usar [`seq`](https://github.com/acmepy/seq) como motor de persistencia. Para SQLite se requiere instalar también `better-sqlite3`.

```js
import { Seq, SQLiteAdapter } from "seq";
import { SeqAdapter } from "iam/adapters";
import { Auth } from "iam/express";

const sqlite = new SQLiteAdapter({ database: ":memory:" });
const seq = new Seq({ adapter: sqlite, logging: false });
const adapter = new SeqAdapter({ seq });

await seq.init();
await seq.sync();

await adapter.models.User.create({
  id: "admin",
  password: "1234",
  name: "Administrador",
  email: "admin@app.com",
  options: {},
  active: true
});

const auth = new Auth({ adapter });
const session = await auth.login({
  username: "admin",
  password: "1234",
  options: { empresa: 1 }
});

console.log(session.user.id); // admin
```

## Exportaciones

```js
import { RBAC, MemoryAdapter } from "iam";
import { Auth, createAuth } from "iam/express";
import { MemoryAdapter, SeqAdapter } from "iam/adapters";
import { auth, can, signJwt, verifyJwt } from "iam/express";
import { auth, can } from "iam/browser";
```

## Pruebas

```sh
npm test
```

## Licencia

MIT
