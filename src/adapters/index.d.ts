import type {
  Adapter,
  AdapterData,
  Id,
  KeyValueStorage,
  PermissionData,
  RoleData,
  RolePermissionData,
  SessionData,
  UserData,
  UserRoleData
} from "../types.js";

export class MemoryAdapter implements Adapter {
  constructor(data?: AdapterData);
  users: UserData[];
  roles: RoleData[];
  permissions: PermissionData[];
  userRoles: UserRoleData[];
  rolePermissions: RolePermissionData[];
  sessions: SessionData[];
  findUserByUsername(username: string): Promise<UserData | null>;
  findUserById(id: Id): Promise<UserData | null>;
  verifyPassword(user: UserData, password: string): Promise<boolean>;
  createSession(session: SessionData): Promise<SessionData>;
  findSessionById(id: Id): Promise<SessionData | null>;
  findSessionByToken(token: string): Promise<SessionData | null>;
  findActiveSessionByUserId(userId: Id): Promise<SessionData | null>;
  deactivateSession(id: Id): Promise<SessionData | null>;
  updateSession(id: Id, values: Partial<SessionData>): Promise<SessionData | null>;
  findRolesByUserId(userId: Id): Promise<RoleData[]>;
  findPermissionsByUserId(userId: Id): Promise<PermissionData[]>;
}

export class LocalStorageAdapter extends MemoryAdapter {
  constructor(options?: { storage?: KeyValueStorage | null; key?: string; data?: AdapterData });
  storage?: KeyValueStorage | null;
  key: string;
  save(): void;
}

export class IndexedDBAdapter extends MemoryAdapter {
  constructor(options?: {
    indexedDB?: unknown;
    dbName?: string;
    storeName?: string;
    data?: AdapterData;
  });
  indexedDB?: unknown;
  dbName: string;
  storeName: string;
  db: unknown | null;
  init(): Promise<this>;
  load(): Promise<this>;
  save(): Promise<this>;
  open(): Promise<unknown>;
}

export class SequelizeAdapter implements Adapter {
  constructor(options?: { sequelize?: unknown; models?: Record<string, unknown> });
  sequelize?: unknown;
  models: Record<string, unknown>;
  findUserByUsername(username: string): Promise<UserData | null>;
  findUserById(id: Id): Promise<UserData | null>;
  verifyPassword(user: UserData, password: string): Promise<boolean>;
  createSession(session: SessionData): Promise<SessionData>;
  findSessionById(id: Id): Promise<SessionData | null>;
  findSessionByToken(token: string): Promise<SessionData | null>;
  findActiveSessionByUserId(userId: Id): Promise<SessionData | null>;
  deactivateSession(id: Id): Promise<SessionData | null>;
  updateSession(id: Id, values: Partial<SessionData>): Promise<SessionData | null>;
  findRolesByUserId(userId: Id): Promise<RoleData[]>;
  findPermissionsByUserId(userId: Id): Promise<PermissionData[]>;
  opOr(): unknown;
}

export class SeqAdapter extends SequelizeAdapter {
  constructor(options?: { seq?: unknown; models?: Record<string, unknown> });
  seq?: unknown;
}
