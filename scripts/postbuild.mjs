/**
 * LombokFuzzer — postbuild
 *
 * Writes the dual-package `type` markers into the built output so Node resolves
 * each format correctly: the root package.json declares `"type": "module"`, so
 * without these markers the CommonJS files in dist/cjs would be loaded as ESM
 * and `require('lombokfuzzer')` would throw. Runs automatically after `build`.
 *
 * Cross-platform (Node-only, no shell dependencies) — works on Windows,
 * macOS, and Linux alike.
 *
 * @license Apache-2.0
 */

import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const markers = [
  { dir: join(root, 'dist', 'cjs'), type: 'commonjs' },
  { dir: join(root, 'dist', 'esm'), type: 'module' },
];

for (const { dir, type } of markers) {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ type }, null, 2) + '\n');
  console.log(`postbuild: wrote ${type} marker → ${join(dir, 'package.json')}`);
}
