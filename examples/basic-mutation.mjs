/**
 * LombokFuzzer — Basic mutation-fuzzing example
 *
 * Fuzzes a deliberately buggy length-prefixed parser and reports the crashes
 * it finds. Run after building:  node examples/basic-mutation.mjs
 *
 * @license Apache-2.0
 */

import { LombokFuzzer, FuzzMode } from '../dist/esm/index.js';

// ─── A target with two planted bugs ─────────────────────────────────────────
// Wire format: [length_byte][payload...]. The parser trusts the length byte
// without validating it against the actual payload — a classic buffer
// over-read. A second, much rarer bug fires on a "CRASH" sentinel string.
function buggyParser(data) {
  if (data.length < 1) return 0;

  const claimedLen = data[0];          // first byte = claimed payload length
  const payload = data.subarray(1);

  // BUG 1 (easy to hit): over-read — claimed length exceeds real payload.
  if (claimedLen > payload.length) {
    throw new RangeError(
      `buffer over-read: header claims ${claimedLen} bytes, only ${payload.length} present`,
    );
  }

  // BUG 2 (rare): sentinel string in the payload.
  const text = new TextDecoder('utf-8', { fatal: false }).decode(payload);
  if (text.includes('CRASH')) {
    throw new Error('sentinel string reached: parser invariant violated');
  }

  return claimedLen;
}

// ─── Configure the fuzzer ───────────────────────────────────────────────────
const fuzzer = new LombokFuzzer({
  name: 'framed-parser-demo',
  mode: FuzzMode.Mutation,
  maxExecutions: 50_000,
  seed: 1337n,
  harness: {
    mode: 'in_process',
    targetFunction: buggyParser,
  },
});

// Seeds are *valid* frames (length byte matches payload length), so the
// fuzzer has to mutate them into an invalid state to trigger the bug.
fuzzer.addSeed(Uint8Array.from([3, 0x61, 0x62, 0x63]));       // len=3, "abc"
fuzzer.addSeed(Uint8Array.from([5, 0x68, 0x65, 0x6c, 0x6c, 0x6f])); // len=5, "hello"
fuzzer.addSeed(Uint8Array.from([0]));                          // len=0, empty

let crashesSeen = 0;
fuzzer.on('crash_found', ({ crash }) => {
  crashesSeen++;
  console.log(`  ⚑ crash #${crashesSeen}: [${crash.severity}] ${crash.category} — ${crash.signal}`);
});

console.log('Fuzzing framed-parser-demo …\n');
const stats = await fuzzer.run();

console.log('\n─── Summary ───────────────────────────────');
console.log(`  Executions   : ${stats.totalExecutions.toLocaleString()}`);
console.log(`  Exec/sec     : ${Math.round(stats.execsPerSecond).toLocaleString()}`);
console.log(`  Corpus size  : ${stats.corpusSize}`);
console.log(`  Unique crash : ${stats.uniqueCrashes}`);
console.log(`  Elapsed      : ${(stats.elapsedMs / 1000).toFixed(2)}s`);
