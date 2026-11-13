// Copies brand kit assets (unmodified) into public/brand so Vite serves them at /brand/*.
// Source of truth stays in ../brand — never edit the copies.
import { cpSync, existsSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "../../brand/assets");
const dest = resolve(here, "../public/brand");
if (!existsSync(src)) {
  console.error(`brand kit not found at ${src}`);
  process.exit(1);
}
mkdirSync(dest, { recursive: true });
for (const dir of ["svg", "png", "favicon"]) cpSync(resolve(src, dir), resolve(dest, dir), { recursive: true });
// Browsers request /favicon.ico at the root regardless of <link> tags.
cpSync(resolve(src, "favicon/favicon.ico"), resolve(here, "../public/favicon.ico"));
console.log(`brand assets synced → ${dest}`);
