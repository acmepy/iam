# iam

IAM es una pequena biblioteca para autenticacion, autorizacion y gestion de sesiones en JavaScript.

`iam` ofrece control de acceso basado en roles, middleware para Express, cliente para navegador y adaptadores de persistencia enchufables.

## Instalacion

```sh
npm install iam
```

## Inicio rapido

```js
import { MemoryAdapter, RBAC } from "iam";

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

const rbac = new RBAC({ adapter });
console.log(await rbac.can("admin", "users.list")); // true
```

## RBAC

```js
import { RBAC } from "iam";

const rbac = new RBAC({ adapter });

await rbac.hasRole("admin", "admin");
await rbac.can("admin", "users.list");
```

## Middleware para Express

`iam/express` expone solo dos middlewares publicos: `auth` y `can`.
`auth(options)` se instala una vez con `app.use(...)`, autentica requests con Basic o Bearer JWT, maneja las rutas estandar de sesion y deja `req.session` disponible para las rutas protegidas.

```js
import express from "express";
import { MemoryAdapter } from "iam/adapters";
import { auth, can } from "iam/express";

const app = express();
app.use(express.json());

const adapter = new MemoryAdapter();
const iamOptions = {
  adapter,
  jwt: {
    secret: "replace-with-a-secure-secret",
    expiresIn: "1h"
  }
};

app.use(auth(iamOptions));

app.get("/users", can("users.list"), (req, res) => {
  res.json({
    ok: true,
    data: [
      { id: "admin", name: "Administrador", email: "admin@app.com" }
    ]
  });
});
```

`auth(options)` admite:

- Tokens bearer JWT con `auth({ adapter, jwt: { secret, expiresIn } })`.
- Autenticacion basica con `Authorization: Basic ...`.
- Challenge nativo del navegador con `WWW-Authenticate: Basic realm="IAM"` cuando faltan credenciales.
- Deteccion automatica de estrategia con `auth({ adapter, jwt: { secret } })`.

Rutas manejadas por el middleware:

- `POST /login`: valida credenciales y responde `{ ok: true, data: { ...session, token, expiresIn } }`.
- `GET /session`: requiere Basic o Bearer JWT y responde `{ ok: true, data: { ...session } }`.
- `POST /logout`: desactiva la sesion actual y responde `{ ok: true, data: {} }`.

Formato de respuestas:

```json
{ "ok": true, "data": { "...": "..." } }
```

```json
{ "ok": true, "data": [{ "...": "..." }] }
```

```json
{ "ok": false, "message": "Mensaje de error", "stack": "..." }
```

Ejemplo de login:

```sh
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin@app.com\",\"password\":\"1234\"}"
```

Si las credenciales son invalidas, `POST /login` responde JSON con detalles:

```json
{
  "ok": false,
  "message": "Credenciales invalidas",
  "stack": "...",
  "details": {
    "credentials": "Usuario o clave invalidos"
  }
}
```

Ejemplo de ruta protegida:

```sh
curl http://localhost:3000/users \
  -H "Authorization: Bearer <token>"
```

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

El cliente del navegador puede usar el servidor Express anterior:

- `POST /login` para login con usuario y contrasena.
- `POST /logout` para cerrar sesion.
- `GET /session` para login con token bearer.
- Basic sin credenciales dispara el dialogo nativo del navegador por `WWW-Authenticate`.

## Adaptadores

Adaptadores disponibles:

- `MemoryAdapter`
- `LocalStorageAdapter`
- `IndexedDBAdapter`
- `SequelizeAdapter`
- `SeqAdapter`

Los adaptadores se encargan de la busqueda de usuarios, verificacion de contrasenas, persistencia de sesiones, busqueda de roles y busqueda de permisos.

### SeqAdapter

`SeqAdapter` permite usar [`seq`](https://github.com/acmepy/seq) como motor de persistencia. Para SQLite se requiere instalar tambien `better-sqlite3`.

```js
import { Seq, SQLiteAdapter } from "seq";
import { SeqAdapter } from "iam/adapters";
import { RBAC } from "iam";

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

const rbac = new RBAC({ adapter });

console.log(await rbac.can("admin", "users.list")); // true
```

#### Modelos y tablas personalizadas

`SeqAdapter` y `SequelizeAdapter` pueden recibir modelos ya definidos cuando necesitas controlar completamente la definicion:

```js
const adapter = new SeqAdapter({
  models: {
    User,
    Role,
    Permission,
    UserRole,
    RolePermission,
    Session
  }
});
```

Si solo necesitas cambiar los nombres fisicos de las tablas, podes pasar `tableNames` y dejar que `iam` defina los modelos internos:

```js
const adapter = new SeqAdapter({
  seq,
  tableNames: {
    User: "iam_users",
    Role: "iam_roles",
    Permission: "iam_permissions",
    UserRole: "iam_user_roles",
    RolePermission: "iam_role_permissions",
    Session: "iam_sessions"
  }
});
```

Las claves de `models` y `tableNames` corresponden a los modelos internos de IAM: `User`, `Role`, `Permission`, `UserRole`, `RolePermission` y `Session`.

## Exportaciones

```js
import { RBAC, MemoryAdapter } from "iam";
import { MemoryAdapter, SeqAdapter } from "iam/adapters";
import { auth, can } from "iam/express";
import { auth as browserAuth, can as browserCan } from "iam/browser";
```

## Pruebas

```sh
npm test
```

## Ejemplo SQLite en consola

```sh
npm run example:sqlite
```

El ejemplo usa SQLite en memoria con `SeqAdapter`, crea un usuario admin,
crea una sesion, consulta roles/permisos y cierra la sesion.

## Licencia

MIT
