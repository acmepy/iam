import { AdapterError } from "../core/errors.js";
import { MemoryAdapter } from "./MemoryAdapter.js";

const collections = ["users", "roles", "permissions", "userRoles", "rolePermissions", "sessions"];
const defaultDbName = "iam";
const defaultStoreName = "collections";

export class IndexedDBAdapter extends MemoryAdapter {
  constructor({indexedDB = globalThis.indexedDB, dbName = defaultDbName, storeName = defaultStoreName, data = {} } = {}) {
    super(data);
    this.indexedDB = indexedDB;
    this.dbName = dbName;
    this.storeName = storeName;
    this.db = null;
  }

  async init() {
    await this.load();
    return this;
  }

  async load() {
    const db = await this.open();
    const transaction = db.transaction(this.storeName, "readonly");
    const done = transactionToPromise(transaction);
    const store = transaction.objectStore(this.storeName);
    const requests = collections.map((name) => { return {name, request: store.get(name)}});
    for (const item of requests) {
      const value = await requestToPromise(item.request);
      const name = item.name;
      this[name] = [...(value?.items ?? this[name] ?? [])];
    }
    await done;
    return this;
  }

  async save() {
    const db = await this.open();
    const transaction = db.transaction(this.storeName, "readwrite");
    const done = transactionToPromise(transaction);
    const store = transaction.objectStore(this.storeName);
    for (const name of collections) store.put({ name, items: this[name] }, name);
    await done;
    return this;
  }

  async createSession(session) {
    const result = await super.createSession(session);
    await this.save();
    return result;
  }

  async deactivateSession(id) {
    const result = await super.deactivateSession(id);
    await this.save();
    return result;
  }

  async updateSession(id, values) {
    const result = await super.updateSession(id, values);
    await this.save();
    return result;
  }

  async open() {
    if (!this.indexedDB) throw new AdapterError("IndexedDB no está disponible");
    if (this.db) return this.db;
    const request = this.indexedDB.open(this.dbName, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(this.storeName)) db.createObjectStore(this.storeName);
    };
    this.db = await requestToPromise(request);
    return this.db;
  }
}

function requestToPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new AdapterError("Error en IndexedDB", request.error));
  });
}

function transactionToPromise(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(new AdapterError("Error en transacción IndexedDB", transaction.error));
    transaction.onabort = () => reject(new AdapterError("Transacción IndexedDB abortada", transaction.error));
  });
}
