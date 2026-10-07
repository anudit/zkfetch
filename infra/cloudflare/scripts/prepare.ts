import { writeFileSync } from "node:fs";

// worker-build creates the Wasm entrypoint. Add the Container class export
// without replacing the Rust fetch handler.
writeFileSync("build/entry.ts", `export { default } from "./index.js";\nexport { NotaryContainer } from "../src/container";\n`);
writeFileSync("build/index.d.ts", `declare const handler: ExportedHandler<Env>;\nexport default handler;\n`);
