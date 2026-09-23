import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// Built output goes straight into ../docs so GitHub Pages can serve the site
// from the repo's /docs folder with no extra deploy step or branch.
export default defineConfig({
  plugins: [react()],
  base: "./",
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  build: {
    outDir: "../docs",
    emptyOutDir: false,   // keep report-preview.png and sample-report.html
    assetsDir: "assets",
  },
});
