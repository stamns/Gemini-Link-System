import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5000,
    proxy: {
      // 代理 API 请求到后端
      '/admin': {
        target: 'http://localhost:4500',
        changeOrigin: true,
      },
      '/v1': {
        target: 'http://localhost:4500',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:4500',
        ws: true,
      },
      '/health': {
        target: 'http://localhost:4500',
        changeOrigin: true,
      },
      '/generated_images': {
        target: 'http://localhost:4500',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
