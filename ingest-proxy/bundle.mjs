// Bundle the two Lambda entrypoints into self-contained ESM files. The infra program ships
// `dist/` straight into the Lambda AssetArchive with NO node_modules, so any bare import that
// tsc leaves in place (e.g. @folklore/contracts -> zod) crashes the function at init with
// ERR_MODULE_NOT_FOUND (the 2026-08-19 webhook outage). Bundling inlines the whole dependency
// closure; the tsc pass above still typechecks and feeds vitest.
import { build } from 'esbuild';

await build({
  entryPoints: ['src/dispatcher.ts', 'src/lambdas/handler.ts'],
  outdir: 'dist',
  outbase: 'src',
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'esm',
  // The nodejs20.x runtime ships AWS SDK v3; keep it external so the bundle stays small.
  external: ['@aws-sdk/*'],
  sourcemap: true,
  // zod (via @folklore/contracts) is CJS; give the ESM bundle a require shim.
  banner: {
    js: "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);",
  },
  logLevel: 'info',
});
