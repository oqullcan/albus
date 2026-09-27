// @ts-check
import { defineConfig } from 'astro/config';

// Static site, no adapter. Pure black theme, no webfonts (system stack).
export default defineConfig({
  outDir: './dist',
  build: {
    inlineStylesheets: 'auto',
  },
});
