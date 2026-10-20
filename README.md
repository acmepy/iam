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
  usersRoles: [{ id: 1, userId: "admin", roleId: 1, active: true }],
  rolesPermissions: [{ id: 1, roleId: 1, permissionId: 1, active: true }]
});

const rbac = new RBAC({ adapter });
console.log(await rbac.can("admin", "users.list")); // true
```

## Registro, perfil y recuperacion de contrasena

Habilita el registro expresamente con `auth({ adapter, registration: true, jwt: { secret } })`.
Por defecto el registro esta deshabilitado. Las respuestas mantienen el formato `{ ok: true, data: ... }`.

| Ruta | Cuerpo | Acceso |
| --- | --- | --- |
| `POST /register` | `{ name, email, password }` | Publico, con `registration: true` |
| `PATCH /me` | `{ name?, email? }` | Usuario autenticado |
| `POST /me/password` | `{ currentPassword, password }` | Usuario autenticado |
| `POST /reset-password` | `{ token, password }` | Credencial de recuperacion valida |

El registro devuelve el usuario publico con estado HTTP 201; no inicia sesion. El servidor genera su `id`, lo crea activo, con `options: {}` y sin roles. El correo no es unico. Usa el `id` devuelto como `username` para identificar inequívocamente la cuenta en el login; la busqueda existente por nombre o correo devuelve la primera coincidencia.

La edicion opera exclusivamente sobre la identidad autenticada. Registro y perfil rechazan campos adicionales, incluidos roles, permisos, estado y `options`. Nombre y correo se recortan y admiten hasta 150 caracteres; el correo debe tener formato valido. Las contrasenas no vacias admiten hasta 255 caracteres y conservan el mecanismo de almacenamiento y comparacion existente. `options` en login conserva su comportamiento previo.

Para generar un enlace, llama esta funcion **desde el servidor**, despues de autorizar la recuperacion de la cuenta por su `userId`:

```js
import { createPasswordReset } from "iam/express";

const { url, expiresAt } = await createPasswordReset({
  adapter,
  userId: "id-exacto-del-usuario",
  resetUrl: "https://mi-aplicacion.com/restablecer",
  expiresIn: 1800
});
```

`url` contiene el parametro `token`; `expiresAt` es el vencimiento en segundos Unix. `expiresIn` se expresa en segundos y vale 1800 por defecto. La URL base la configura el servidor. No existe una ruta publica que genere o entregue estos enlaces.

La pantalla de la aplicacion debe extraer `token` del enlace y enviar `POST /reset-password` con la nueva contrasena. IAM no crea esa pantalla ni envia correos, SMS o WhatsApp. Abrir el enlace no consume la credencial: se consume al restablecer la contrasena correctamente.

Se persiste una huella SHA-256 de la credencial aleatoria, no el token del enlace. Cambiar o restablecer la contrasena invalida todas las sesiones y credenciales de recuperacion de esa cuenta; requiere un nuevo login y no reactiva usuarios desactivados.

### Persistencia

Los modelos SQL incluyen la nueva tabla `passwordResets`, configurable con `tableNames.passwordResets`. Contiene `id` (huella de 64 caracteres), `userId`, `expiresAt` (segundos Unix) y timestamps. En bases existentes hay que crear esta tabla antes de usar recuperacion; con modelos personalizados hay que proporcionar `models.passwordResets`. No se agrega unicidad al correo ni se cambia la tabla de usuarios.

Las operaciones SQL de cambio y restablecimiento necesitan transacciones: `SeqAdapter` usa `seq.transaction` y `SequelizeAdapter` usa `sequelize.transaction`. La eliminacion condicional de la credencial y el cambio de contrasena se ejecutan junto con la invalidacion de sesiones en la misma transaccion. SQLite en Seq rechaza transacciones simultaneas en una conexion; una solicitud rechazada por ese motivo puede reintentarse.

Los adaptadores propios deben implementar `createUser`, `updateUser`, `createPasswordReset`, `changePassword` y `resetPassword` para las funciones correspondientes. `changePassword(userId, expectedPassword, password)` comprueba la contrasena almacenada esperada; `resetPassword(id, password, timestamp)` recibe la huella y valida el vencimiento. Ambos devuelven un booleano y deben invalidar sesiones y credenciales de recuperacion atomicamente. Los adaptadores de memoria y almacenamiento del navegador son para uso local; no coordinan recuperaciones entre procesos o pestanas.

El cliente `iam/browser` expone `auth.register({ name, email, password })`, `auth.updateProfile({ name, email })`, `auth.changePassword(currentPassword, password)` y `auth.resetPassword(token, password)`. El cambio y restablecimiento exitosos limpian la sesion local.

## RBAC

```js
import { RBAC } from "iam";

const rbac = new RBAC({ adapter });

await rbac.hasRole("admin", "admin");
await rbac.can("admin", "users.list");
```

## Middleware para Express

`iam/express` expone los middlewares publicos `auth` y `can`, y `verifyJwt` para verificar un token JWT HS256 fuera del middleware. `verifyJwt` devuelve el payload verificado, incluido `exp` cuando el token lo tiene.
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
- Si `jwt.expiresIn` se omite o es `null`, los nuevos tokens vencen en 365 dias (31536000 segundos). Un valor explicito conserva la duracion configurada.
- Autenticacion basica con `Authorization: Basic ...`.
- Challenge nativo del navegador con `WWW-Authenticate: Basic realm="IAM"` cuando faltan credenciales.
- Deteccion automatica de estrategia con `auth({ adapter, jwt: { secret } })`.

Rutas manejadas por el middleware:

- `POST /login`: valida credenciales y responde `{ ok: true, data: { ...session, token, expiresIn } }`.
- `GET /session`: requiere Basic o Bearer JWT y responde `{ ok: true, data: { ...session } }`.
- `POST /logout`: sin cuerpo, requiere `Authorization: Bearer <token>`, desactiva exclusivamente la sesion del token y responde `{ ok: true, data: {} }`. Un `sessionId` enviado en el cuerpo se ignora; Basic no permite cerrar sesiones por esta ruta.

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

| Metodo del cliente | Operacion del servidor |
| --- | --- |
| `auth.register({ name, email, password })` | `POST /register`; requiere registro habilitado en el servidor |
| `auth.login({ username, password, options })` | `POST /login` |
| `auth.login({ token })` | `GET /session` con Bearer |
| `auth.updateProfile({ name, email })` | `PATCH /me` con Bearer; ambos campos son opcionales, pero debe enviarse al menos uno |
| `auth.changePassword(currentPassword, password)` | `POST /me/password` con Bearer |
| `auth.resetPassword(token, password)` | `POST /reset-password`; no requiere sesion iniciada |
| `auth.logout()` | `POST /logout` con Bearer y sin cuerpo |
| `auth.getSession()` | Devuelve la sesion local, sin consultar al servidor |

`register` devuelve el usuario creado sin iniciar sesion. `updateProfile` actualiza tambien el usuario de la sesion local. El cambio o restablecimiento de contrasena y el logout limpian la sesion local cuando terminan correctamente.

El token para `resetPassword` es el parametro `token` del enlace de recuperacion. El enlace se genera exclusivamente en el servidor con `createPasswordReset`; el cliente no emite credenciales de recuperacion ni envia notificaciones.

## OpenAPI y Postman por permisos

`iam/docs` permite filtrar definiciones OpenAPI y colecciones Postman antes de mostrarlas al usuario. Las rutas publicas se conservan por defecto y las rutas protegidas deben declarar permisos con `x-permission`, `x-permissions`, `x-iam-permission` o `x-iam-permissions`.

```js
import { filterOpenApiByPermissions, filterPostmanByPermissions } from "iam/docs";

const visibleOpenApi = filterOpenApiByPermissions(openApiDocument, session.permissions);
const visibleCollection = filterPostmanByPermissions(postmanCollection, session.permissions);
```

Ejemplo OpenAPI:

```json
{
  "paths": {
    "/users": {
      "get": {
        "x-permission": "users.list",
        "responses": {}
      },
      "post": {
        "x-permission": "users.create",
        "responses": {}
      }
    }
  }
}
```

Ejemplo Postman:

```json
{
  "item": [
    {
      "name": "List users",
      "x-permission": "users.list",
      "request": { "method": "GET", "url": "/users" }
    }
  ]
}
```

`can("users.list")` tambien expone metadata (`permission`, `permissions` e `iam`) para que herramientas de documentacion puedan leer el permiso asociado al middleware.

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

await adapter.models.users.create({
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

### Logging de autenticación y permisos

`auth` usa la misma convención de `logging` que `Seq`: por defecto registra eventos; usa `false` para desactivarlos o un objeto con handlers por nivel. Los eventos no incluyen contraseñas, tokens ni secretos.

La opción `getContext` de `auth` permite consultar el contexto actual de la aplicación: `auth({ adapter, getContext, logging: logger })`. Los logs incluyen `txId` cuando `getContext()?.txId` tiene un valor distinto de `null` o `undefined`. La función se consulta en cada evento y puede devolver otros datos de contexto; estos no se agregan al log.

```js
app.use(auth({
  adapter,
  jwt: { secret: process.env.JWT_SECRET },
  logging: {
    info: console.log,
    trace: console.debug,
    error: console.error
  }
}));
```

Se emite `trace` para accesos autenticados y permisos concedidos, `info` para inicios/cierres de sesión y permisos denegados, y `error` para errores internos.

Al igual que en `Seq`, se puede pasar directamente una instancia de `com.acmepy.logger-js`:

```js
import { createLogger, logger, LEVELS } from "com.acmepy.logger-js";

createLogger({
  name: "[iam]",
  displayConsole: true,
  level: LEVELS.INFO
});

app.use(auth({
  adapter,
  jwt: { secret: process.env.JWT_SECRET },
  logging: logger
}));
```

`SeqAdapter` tambien puede emitir cambios auditables de sesion sin acoplarse a ningun sistema de auditoria especifico:

```js
const adapter = new SeqAdapter({
  seq,
  auditable: {
    tableName: "iam_sessions",
    write: async (change) => {
      // change: { module, resource, tableName, action, rowId, old, new }
    }
  }
});
```

#### Modelos y tablas personalizadas

`SeqAdapter` y `SequelizeAdapter` pueden recibir modelos ya definidos cuando necesitas controlar completamente la definicion:

```js
const adapter = new SeqAdapter({
  models: {
    users,
    roles,
    permissions,
    usersRoles,
    rolesPermissions,
    sessions
  }
});
```

Si solo necesitas cambiar los nombres fisicos de las tablas, podes pasar `tableNames` y dejar que `iam` defina los modelos internos:

```js
const adapter = new SeqAdapter({
  seq,
  tableNames: {
    users: "iam_users",
    roles: "iam_roles",
    permissions: "iam_permissions",
    usersRoles: "iam_user_roles",
    rolesPermissions: "iam_role_permissions",
    sessions: "iam_sessions"
  }
});
```

Las claves de `models` y `tableNames` corresponden a los modelos internos de IAM: `users`, `roles`, `permissions`, `usersRoles`, `rolesPermissions` y `sessions`.

## Exportaciones

```js
import { RBAC, MemoryAdapter } from "iam";
import { MemoryAdapter, SeqAdapter } from "iam/adapters";
import { auth, can } from "iam/express";
import { auth as browserAuth, can as browserCan } from "iam/browser";
import { filterOpenApiByPermissions, filterPostmanByPermissions } from "iam/docs";
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

## Ejemplo auditable

```sh
npm run example:auditable
```

El ejemplo usa `SeqAdapter` con `auditable`, crea una tabla `audit`, guarda alli los
cambios de sesion de IAM y luego muestra las filas persistidas.

## Licencia

MIT
