import { defineConfig } from "astro/config";
import { readFileSync } from "node:fs";

const hovelVersion = readFileSync(new URL("./version.txt", import.meta.url), "utf8").trim();

export default defineConfig({
  output: "static",
  trailingSlash: "never",
  compressHTML: false,
  build: {
    format: "preserve",
  },
  outDir: "./dist",
  cacheDir: `./${process.env.ASTRO_CACHE_DIR ?? "dist/.astro-cache"}`,
  vite: {
    define: {
      __HOVEL_RELEASE_TAG__: JSON.stringify(`v${hovelVersion}`),
      __HOVEL_VERSION__: JSON.stringify(hovelVersion),
    },
    build: {
      sourcemap: false,
    },
  },
});
