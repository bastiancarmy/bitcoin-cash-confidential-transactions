// build.mjs
import esbuild from 'esbuild';

esbuild
  .build({
    entryPoints: [
      'src/demo.js',
      'src/fund_schnorr.js',
      'src/index_pool_demo.js',
      'src/tests/core.test.js',
      'src/tests/confidential.test.js',
      'src/tests/mode-switch.test.js',
      'src/tests/psbt_rpa.test.js',
    ],
    bundle: true,
    platform: 'node',
    target: 'node20',
    outdir: 'dist',
    format: 'cjs',
    banner: {
      js: '#!/usr/bin/env node',
    },
    treeShaking: false,
    minify: false,
    keepNames: true,
    sourcemap: true,
    logLevel: 'warning',
    external: [
      'paillier-bigint',
      'bigint-crypto-utils',
      'tty',
      'os',
      '@bitauth/libauth',
    ],
    loader: {
      '.cash': 'text',
      '.casm': 'text',
    },
  })
  .catch(() => process.exit(1));
