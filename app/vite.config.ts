import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Porta fixa: o tauri.conf.json aponta para 5173 e o Tauri não tolera
// que o Vite escolha outra porta quando essa está ocupada.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  build: {
    // WebView2 no Windows e WebKitGTK no Linux: alvo conservador porque
    // WebKitGTK de distribuição antiga não acompanha o Chrome.
    target: "es2021",
    sourcemap: process.env.TAURI_ENV_DEBUG === "true",
    minify: process.env.TAURI_ENV_DEBUG === "true" ? false : "esbuild",
  },
});
