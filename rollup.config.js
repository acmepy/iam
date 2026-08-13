import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const entries = [
  ["src/express/index.js", "dist/express.js"],
  ["src/docs/index.js", "dist/docs.js"],
  ["src/browser/index.js", "dist/browser.js"]
];

function declarations() {
  return {
    name: "declarations",
    buildStart() {
      rmSync("dist", { recursive: true, force: true });
    },
    writeBundle() {
      writeDeclarations();
    }
  };
}

function writeDeclarations() {
  cpDeclaration("src/express/index.d.ts", "dist/express.d.ts");
  cpDeclaration("src/docs/index.d.ts", "dist/docs.d.ts");
  cpDeclaration("src/browser/index.d.ts", "dist/browser.d.ts");
  writeFileSync("dist/index.d.ts", 'export * from "./express.js";\n');
}

function cpDeclaration(source, target) {
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, readDeclaration(source));
}

function readDeclaration(source) {
  return readFileSync(source, "utf8").replaceAll("../types.js", "./types.js");
}

export default entries.map(([input, file], index) => ({
  input,
  external: (id) => !id.startsWith(".") && !id.startsWith("/") && !id.match(/^[A-Za-z]:[\\/]/),
  output: {
    file,
    format: "esm",
  },
  plugins: index === 0 ? [declarations()] : []
}));
