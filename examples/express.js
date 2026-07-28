import express from "express";
import { MemoryAdapter } from "../src/adapters/index.js";
import { auth, can } from "../src/express/index.js";

const app = express();
const port = process.env.PORT ?? 3000;
const secret = process.env.JWT_SECRET ?? "replace-with-a-secure-secret";

app.use(express.json());

const adapter = new MemoryAdapter({
  users: [
    {
      id: "admin",
      password: "12345",
      name: "Administrador",
      email: "admin@app.com",
      options: {},
      active: true
    }
  ],
  roles: [{ id: 1, role: "admin", active: true }],
  permissions: [{ id: 1, permission: "users.list", title: "List users", active: true }],
  userRoles: [{ id: 1, userId: "admin", roleId: 1, active: true }],
  rolePermissions: [{ id: 1, roleId: 1, permissionId: 1, active: true }]
});

app.use(auth({adapter, jwt: {secret, expiresIn: "1h"}}));

app.get("/users", can("users.list"), (req, res) => {
  res.json({
    ok: true,
    data: [
      { id: "admin", name: "Administrador", email: "admin@app.com" }
    ]
  });
});

app.listen(port, () => {
  console.log(`Express IAM example listening on http://localhost:${port}`);
  console.log("Login with:");
  console.log(`curl -X POST http://localhost:${port}/login -H "Content-Type: application/json" -d "{\\"username\\":\\"admin@app.com\\",\\"password\\":\\"12345\\"}"`);
});
