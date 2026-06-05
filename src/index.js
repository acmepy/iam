export * from "./core/index.js";
export * from "./adapters/index.js";

import { Auth } from "./core/index.js";
export function createAuth(adapter = new MemoryAdapter()) {
    return new Auth({ adapter });
}
