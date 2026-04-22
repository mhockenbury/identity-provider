import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Dev server proxies the two backends so the SPA calls same-origin
// (`/api/docs/...`, `/api/admin/...`) and we skip CORS in local dev.
// Production can do the same behind one reverse proxy, or enable
// CORS on each backend via ALLOWED_ORIGINS.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api/docs': {
        target: 'http://localhost:8083',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/docs/, ''),
      },
      '/api/admin': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/admin/, '/admin/api'),
      },
    },
  },
})
