import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Bind mount do Docker Desktop (Windows/Mac) não propaga eventos de
    // filesystem nativos para dentro do container — sem polling, o HMR
    // simplesmente não percebe os arquivos mudando.
    watch: { usePolling: true, interval: 300 },
  },
});
