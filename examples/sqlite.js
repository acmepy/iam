import { Seq, SQLiteAdapter } from "seq";
import { RBAC } from "../src/core/index.js";
import { SeqAdapter } from "../src/adapters/index.js";
import { Auth } from "../src/express/index.js";

const sqlite = new SQLiteAdapter({ database: ":memory:" });
const seq = new Seq({ adapter: sqlite, logging: false });
const adapter = new SeqAdapter({ seq });

try {
  await seq.init();
  await seq.sync();

  await seed(adapter.models);

  const auth = new Auth({ adapter });
  const rbac = new RBAC({ adapter });

  const session = await auth.login({
    username: "admin@app.com",
    password: "1234",
    options: { empresa: 1, sucursal: 2 }
  });

  console.log("Sesion creada:");
  console.log(session);

  console.log("Roles:");
  console.log(await rbac.getRoles(session.user.id));

  console.log("Puede listar usuarios?");
  console.log(await rbac.can(session.user.id, "users.list"));

  await auth.logout(session.id);

  console.log("Sesion cerrada:");
  console.log(await adapter.findSessionById(session.id));
} finally {
  await seq.close();
}

async function seed(models) {
  await models.User.create({
    id: "admin",
    password: "1234",
    name: "Administrador",
    email: "admin@app.com",
    options: {},
    active: true
  });

  const role = await models.Role.create({
    role: "admin",
    active: true
  });

  const permission = await models.Permission.create({
    permission: "users.list",
    title: "List users",
    active: true
  });

  await models.UserRole.create({
    userId: "admin",
    roleId: role.getDataValue("id"),
    active: true
  });

  await models.RolePermission.create({
    roleId: role.getDataValue("id"),
    permissionId: permission.getDataValue("id"),
    active: true
  });
}
