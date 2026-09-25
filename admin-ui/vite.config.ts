import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Served by sns-admin from embedded assets at the site root.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: { outDir: "dist", assetsDir: "assets", emptyOutDir: true },
  server: {
    // Dev proxy so `npm run dev` talks to a locally running sns-admin.
    proxy: { "/api": "http://127.0.0.1:7731" },
  },
});
