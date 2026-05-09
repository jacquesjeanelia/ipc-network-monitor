import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/** Vite is only used as the dev server for `tauri dev` (HMR). The UI talks to Rust via Tauri IPC. */
export default defineConfig({
  base: "./",
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
  },
});
