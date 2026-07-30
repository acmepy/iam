import { DataTypes, Seq, SQLiteAdapter } from "seq";
import { SeqAdapter } from "../src/adapters/index.js";

const sqlite = new SQLiteAdapter({ database: ":memory:" });
const seq = new Seq({ adapter: sqlite, logging: false });
const Audit = defineAuditModel(seq);
const adapter = new SeqAdapter({
  seq,
  auditable: {
    tableName: "iam_sessions",
    write: (change) => writeAudit(Audit, change)
  }
});

try {
  await seq.init();
  await seq.sync();
  await seed(adapter.models);

  const session = await adapter.createSession({
    id: "session-1",
    userId: "admin",
    token: null,
    options: { empresa: 1 },
    active: true
  });

  await adapter.updateSession(session.id, { token: "session-token" });
  await adapter.deactivateSession(session.id);

  const rows = await Audit.findAll({ order: [["id", "ASC"]] });

  console.log("Filas guardadas en audit:");
  console.log(JSON.stringify(rows.map((row) => row.toJSON()), null, 2));
} finally {
  await seq.close();
}

function defineAuditModel(seq) {
  return seq.define("audit", {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    txId: { type: DataTypes.STRING(50), allowNull: false },
    clientIp: { type: DataTypes.STRING(50), allowNull: false },
    userId: { type: DataTypes.STRING(100), allowNull: true },
    tableName: { type: DataTypes.STRING(100), allowNull: false },
    rowId: { type: DataTypes.STRING(100), allowNull: false },
    action: { type: DataTypes.STRING(20), allowNull: false },
    old: { type: DataTypes.JSON },
    new: { type: DataTypes.JSON }
  }, { tableName: "audit", timestamps: true });
}

async function writeAudit(AuditModel, change) {
  await AuditModel.create({
    txId: "",
    clientIp: "",
    userId: change.new?.userId || change.old?.userId || null,
    tableName: change.tableName,
    rowId: String(change.rowId || ""),
    action: change.action,
    old: jsonSafe(change.old),
    new: jsonSafe(change.new)
  });
}

function jsonSafe(value) {
  if (!value || typeof value !== "object") return {};
  return JSON.parse(JSON.stringify(value));
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
}
