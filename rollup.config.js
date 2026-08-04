import { cpSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { dirname, join, relative } from "node:path";

const entries = [
  ["src/index.js", "dist/index.js"],
  ["src/adapters/index.js", "dist/adapters/index.js"],
  ["src/express/index.js", "dist/express/index.js"],
  ["src/docs/index.js", "dist/docs/index.js"],
  ["src/browser/index.js", "dist/browser/index.js"]
];

function declarations() {
  return {
    name: "declarations",
    buildStart() {
      rmSync("dist", { recursive: true, force: true });
    },
    writeBundle() {
      copyDeclarations("src", "dist");
    }
  };
}

function copyDeclarations(from, to) {
  for (const entry of readdirSync(from, { withFileTypes: true })) {
    const source = join(from, entry.name);
    const target = join(to, relative("src", source));

    if (entry.isDirectory()) {
      copyDeclarations(source, to);
      continue;
    }

    if (!entry.name.endsWith(".d.ts")) continue;
    mkdirSync(dirname(target), { recursive: true });
    cpSync(source, target);
  }
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
