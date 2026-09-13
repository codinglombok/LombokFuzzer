/**
 * LombokFuzzer — Mutation Engine
 *
 * Implements 15 mutation strategies from classical (AFL bit-flip) to modern
 * (structure-aware, grammar-guided, token-level). Each strategy is a pure
 * function: (input, prng, context) → mutated output.
 *
 * @license Apache-2.0
 */

import type { MutatorConfig, FuzzInput, DictionaryEntry } from '../core/types.js';
import { MutatorStrategy } from '../core/types.js';
import type { PRNG } from '../utils/prng.js';

/** Result of a single mutation pass. */
export interface MutationResult {
  data: Uint8Array;
  strategies: MutatorStrategy[];
}

/** "Interesting" values that historically find bugs (from AFL). */
const INTERESTING_8 = new Int8Array([
  -128, -1, 0, 1, 16, 32, 64, 100, 127,
]);
const INTERESTING_16 = new Int16Array([
  -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767,
]);
const INTERESTING_32 = new Int32Array([
  -2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647,
]);

export class MutationEngine {
  private readonly config: MutatorConfig;
  private readonly prng: PRNG;
  private readonly dictionary: DictionaryEntry[] = [];
  private readonly strategyFns: Map<MutatorStrategy, MutatorFn>;

  constructor(config: MutatorConfig, prng: PRNG) {
    this.config = config;
    this.prng = prng;

    this.strategyFns = new Map<MutatorStrategy, MutatorFn>([
      [MutatorStrategy.BitFlip, this.bitFlip.bind(this)],
      [MutatorStrategy.ByteFlip, this.byteFlip.bind(this)],
      [MutatorStrategy.ArithmeticInc, this.arithInc.bind(this)],
      [MutatorStrategy.ArithmeticDec, this.arithDec.bind(this)],
      [MutatorStrategy.InterestingValues, this.interestingValues.bind(this)],
      [MutatorStrategy.DictionaryInsert, this.dictInsert.bind(this)],
      [MutatorStrategy.DictionaryOverwrite, this.dictOverwrite.bind(this)],
      [MutatorStrategy.Havoc, this.havoc.bind(this)],
      [MutatorStrategy.Splice, this.splice.bind(this)],
      [MutatorStrategy.Trim, this.trim.bind(this)],
      [MutatorStrategy.Extend, this.extend.bind(this)],
      [MutatorStrategy.StructureAware, this.structureAware.bind(this)],
      [MutatorStrategy.GrammarGuided, this.grammarGuided.bind(this)],
      [MutatorStrategy.TokenLevel, this.tokenLevel.bind(this)],
    ]);
  }

  /** Mutate an input using configured strategies. */
  mutate(
    input: Uint8Array,
    maxSize: number,
    corpus: ReadonlyArray<FuzzInput>,
  ): MutationResult {
    const enabled = this.config.strategies;
    const strategy = this.prng.pick(enabled);
    const fn = this.strategyFns.get(strategy);

    if (!fn) {
      return { data: cloneBytes(input), strategies: [] };
    }

    const mutated = fn(input, maxSize, corpus);
    return {
      data: mutated.length > maxSize ? mutated.slice(0, maxSize) : mutated,
      strategies: [strategy],
    };
  }

  /** Havoc: stack multiple random mutations. */
  private havoc(
    input: Uint8Array,
    maxSize: number,
    corpus: ReadonlyArray<FuzzInput>,
  ): Uint8Array {
    let buf = cloneBytes(input);
    const rounds = 1 + this.prng.nextRange(this.config.maxHavocStack);
    // strategies tracked in MutationResult

    const allStrats: MutatorFn[] = [
      this.bitFlip.bind(this),
      this.byteFlip.bind(this),
      this.arithInc.bind(this),
      this.arithDec.bind(this),
      this.interestingValues.bind(this),
      this.trim.bind(this),
      this.extend.bind(this),
    ];

    if (this.dictionary.length > 0) {
      allStrats.push(this.dictInsert.bind(this), this.dictOverwrite.bind(this));
    }

    for (let i = 0; i < rounds; i++) {
      const fn = this.prng.pick(allStrats);
      buf = fn(buf, maxSize, corpus);
    }

    return buf;
  }

  // ─── Deterministic stages ───────────────────────────────────────────────

  /** Flip 1/2/4 random bits. */
  private bitFlip(input: Uint8Array, _maxSize: number): Uint8Array {
    if (input.length === 0) return input;
    const buf = cloneBytes(input);
    const numBits = this.prng.pick([1, 2, 4]);
    const startBit = this.prng.nextRange(buf.length * 8);

    for (let i = 0; i < numBits; i++) {
      const bit = (startBit + i) % (buf.length * 8);
      const byteIdx = bit >> 3;
      const bitIdx = bit & 7;
      buf[byteIdx]! ^= (1 << bitIdx);
    }

    return buf;
  }

  /** Flip 1/2/4 random bytes. */
  private byteFlip(input: Uint8Array, _maxSize: number): Uint8Array {
    if (input.length === 0) return input;
    const buf = cloneBytes(input);
    const numBytes = Math.min(this.prng.pick([1, 2, 4]), buf.length);
    const start = this.prng.nextRange(buf.length - numBytes + 1);

    for (let i = 0; i < numBytes; i++) {
      buf[start + i]! ^= 0xFF;
    }

    return buf;
  }

  /** Add small random value to a byte/word/dword. */
  private arithInc(input: Uint8Array, _maxSize: number): Uint8Array {
    if (input.length === 0) return input;
    const buf = cloneBytes(input);
    const width = this.prng.pick([1, 2, 4].filter(w => w <= buf.length));
    const pos = this.prng.nextRange(buf.length - width + 1);
    const delta = 1 + this.prng.nextRange(35);

    if (width === 1) {
      buf[pos] = ((buf[pos]! + delta) & 0xFF);
    } else if (width === 2) {
      const val = (buf[pos]! | (buf[pos + 1]! << 8)) + delta;
      buf[pos] = val & 0xFF;
      buf[pos + 1] = (val >> 8) & 0xFF;
    } else {
      let val = buf[pos]! | (buf[pos + 1]! << 8) | (buf[pos + 2]! << 16) | (buf[pos + 3]! << 24);
      val = (val + delta) >>> 0;
      buf[pos] = val & 0xFF;
      buf[pos + 1] = (val >> 8) & 0xFF;
      buf[pos + 2] = (val >> 16) & 0xFF;
      buf[pos + 3] = (val >> 24) & 0xFF;
    }

    return buf;
  }

  /** Subtract small random value from a byte/word/dword. */
  private arithDec(input: Uint8Array, _maxSize: number): Uint8Array {
    if (input.length === 0) return input;
    const buf = cloneBytes(input);
    const width = this.prng.pick([1, 2, 4].filter(w => w <= buf.length));
    const pos = this.prng.nextRange(buf.length - width + 1);
    const delta = 1 + this.prng.nextRange(35);

    if (width === 1) {
      buf[pos] = ((buf[pos]! - delta) & 0xFF);
    } else if (width === 2) {
      const val = (buf[pos]! | (buf[pos + 1]! << 8)) - delta;
      buf[pos] = val & 0xFF;
      buf[pos + 1] = (val >> 8) & 0xFF;
    } else {
      let val = buf[pos]! | (buf[pos + 1]! << 8) | (buf[pos + 2]! << 16) | (buf[pos + 3]! << 24);
      val = (val - delta) >>> 0;
      buf[pos] = val & 0xFF;
      buf[pos + 1] = (val >> 8) & 0xFF;
      buf[pos + 2] = (val >> 16) & 0xFF;
      buf[pos + 3] = (val >> 24) & 0xFF;
    }

    return buf;
  }

  /** Replace byte/word/dword with "interesting" boundary value. */
  private interestingValues(input: Uint8Array, _maxSize: number): Uint8Array {
    if (input.length === 0) return input;
    const buf = cloneBytes(input);
    const width = this.prng.pick([1, 2, 4].filter(w => w <= buf.length));
    const pos = this.prng.nextRange(buf.length - width + 1);

    if (width === 1) {
      const val = this.prng.pick(Array.from(INTERESTING_8)) & 0xFF;
      buf[pos] = val;
    } else if (width === 2) {
      const val = this.prng.pick(Array.from(INTERESTING_16));
      buf[pos] = val & 0xFF;
      buf[pos + 1] = (val >> 8) & 0xFF;
    } else {
      const val = this.prng.pick(Array.from(INTERESTING_32));
      buf[pos] = val & 0xFF;
      buf[pos + 1] = (val >> 8) & 0xFF;
      buf[pos + 2] = (val >> 16) & 0xFF;
      buf[pos + 3] = (val >> 24) & 0xFF;
    }

    return buf;
  }

  /** Insert a dictionary token at a random position. */
  private dictInsert(input: Uint8Array, maxSize: number): Uint8Array {
    if (this.dictionary.length === 0) return cloneBytes(input);
    const entry = this.prng.pick(this.dictionary);
    const pos = this.prng.nextRange(input.length + 1);
    const newLen = Math.min(input.length + entry.value.length, maxSize);

    const buf = new Uint8Array(newLen);
    buf.set(input.subarray(0, pos), 0);
    const tokenLen = Math.min(entry.value.length, newLen - pos);
    buf.set(entry.value.subarray(0, tokenLen), pos);
    const remaining = Math.min(input.length - pos, newLen - pos - tokenLen);
    if (remaining > 0) {
      buf.set(input.subarray(pos, pos + remaining), pos + tokenLen);
    }

    entry.hitCount++;
    return buf;
  }

  /** Overwrite at a random position with a dictionary token. */
  private dictOverwrite(input: Uint8Array, _maxSize: number): Uint8Array {
    if (this.dictionary.length === 0 || input.length === 0) return cloneBytes(input);
    const entry = this.prng.pick(this.dictionary);
    const pos = this.prng.nextRange(input.length);

    const buf = cloneBytes(input);
    const len = Math.min(entry.value.length, buf.length - pos);
    buf.set(entry.value.subarray(0, len), pos);

    entry.hitCount++;
    return buf;
  }

  /** Splice: crossover two corpus entries. */
  private splice(
    input: Uint8Array,
    maxSize: number,
    corpus: ReadonlyArray<FuzzInput>,
  ): Uint8Array {
    if (corpus.length < 2) return cloneBytes(input);

    const other = this.prng.pick(corpus);
    if (other.data.length === 0 || input.length === 0) return cloneBytes(input);

    const splitA = this.prng.nextRange(input.length);
    const splitB = this.prng.nextRange(other.data.length);

    const partA = input.subarray(0, splitA);
    const partB = other.data.subarray(splitB);

    const newLen = Math.min(partA.length + partB.length, maxSize);
    const buf = new Uint8Array(newLen);
    buf.set(partA, 0);
    if (partA.length < newLen) {
      buf.set(partB.subarray(0, newLen - partA.length), partA.length);
    }

    return buf;
  }

  /** Trim: delete a random chunk. */
  private trim(input: Uint8Array, _maxSize: number): Uint8Array {
    if (input.length <= 1) return cloneBytes(input);
    const delLen = 1 + this.prng.nextRange(Math.min(input.length - 1, 32));
    const pos = this.prng.nextRange(input.length - delLen + 1);

    const buf = new Uint8Array(input.length - delLen);
    buf.set(input.subarray(0, pos), 0);
    buf.set(input.subarray(pos + delLen), pos);
    return buf;
  }

  /** Extend: insert random bytes at a random position. */
  private extend(input: Uint8Array, maxSize: number): Uint8Array {
    const addLen = 1 + this.prng.nextRange(Math.min(32, maxSize - input.length));
    if (addLen <= 0) return cloneBytes(input);

    const pos = this.prng.nextRange(input.length + 1);
    const buf = new Uint8Array(input.length + addLen);
    buf.set(input.subarray(0, pos), 0);
    this.prng.fillBytes(buf.subarray(pos, pos + addLen));
    buf.set(input.subarray(pos), pos + addLen);
    return buf;
  }

  /** Structure-aware: parse as chunks (length-prefixed) and mutate one chunk. */
  private structureAware(input: Uint8Array, maxSize: number): Uint8Array {
    // Heuristic: try to find repeated patterns / field boundaries
    // For v0.1.0, we do chunk-based mutation: split at \x00 or \n boundaries
    const delimiters = [0x00, 0x0A, 0x0D, 0x2C, 0x3B]; // NUL, LF, CR, comma, semicolon
    const chunks = splitByDelimiters(input, delimiters);

    if (chunks.length <= 1) {
      return this.havoc(input, maxSize, []);
    }

    // Mutate one random chunk
    const idx = this.prng.nextRange(chunks.length);
    const originalChunk = chunks[idx]!;
    chunks[idx] = this.bitFlip(originalChunk, maxSize);

    return joinChunks(chunks, maxSize);
  }

  /** Grammar-guided: placeholder for grammar engine integration. */
  private grammarGuided(input: Uint8Array, maxSize: number): Uint8Array {
    // Full grammar integration comes in v0.2.0
    // For now, fall back to havoc with smart byte selection
    return this.havoc(input, maxSize, []);
  }

  /** Token-level: identify and mutate text tokens. */
  private tokenLevel(input: Uint8Array, maxSize: number): Uint8Array {
    // Parse as UTF-8 text and operate on tokens (words, numbers, symbols)
    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(input);
    } catch {
      return this.bitFlip(input, maxSize);
    }

    const tokens = tokenize(text);
    if (tokens.length === 0) return cloneBytes(input);

    const idx = this.prng.nextRange(tokens.length);
    const token = tokens[idx]!;

    // Mutate the token based on its type
    tokens[idx] = this.mutateToken(token);

    const result = new TextEncoder().encode(tokens.join(''));
    return result.length <= maxSize ? result : result.slice(0, maxSize);
  }

  private mutateToken(token: string): string {
    // Number → boundary values
    if (/^-?\d+$/.test(token)) {
      const val = parseInt(token, 10);
      const mutations = [0, -1, 1, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
        2147483647, -2147483648, val + 1, val - 1, val * 2, -val];
      return String(this.prng.pick(mutations));
    }

    // Float → boundary values
    if (/^-?\d+\.\d+$/.test(token)) {
      const mutations = ['0.0', '-0.0', 'NaN', 'Infinity', '-Infinity',
        '1e308', '-1e308', '1e-308', '4.9e-324'];
      return this.prng.pick(mutations);
    }

    // String → common attack strings
    if (token.length > 0) {
      const attacks = [
        '', 'A'.repeat(256), 'A'.repeat(4096),
        '%n%n%n%n', '%s%s%s%s',
        '../../../etc/passwd', '..\\..\\..\\windows\\system32',
        "' OR 1=1 --", '" OR 1=1 --',
        '<script>alert(1)</script>', '${7*7}',
        '{{7*7}}', '\x00\x00\x00\x00',
        '\r\n\r\n', '\uFEFF', '\uFFFF',
        token.toUpperCase(), token.toLowerCase(),
        token.split('').reverse().join(''),
      ];
      return this.prng.pick(attacks);
    }

    return token;
  }

  // ─── Dictionary management ──────────────────────────────────────────────

  /** Add a dictionary entry. */
  addDictionary(value: Uint8Array, level: number = 1): void {
    this.dictionary.push({ value: cloneBytes(value), level, hitCount: 0 });
  }

  /** Add dictionary entries from a file (one token per line). */
  addDictionaryTokens(tokens: string[]): void {
    const encoder = new TextEncoder();
    for (const token of tokens) {
      const trimmed = token.trim();
      if (trimmed.length > 0 && !trimmed.startsWith('#')) {
        // Handle quoted strings: "token" or token
        const unquoted = trimmed.startsWith('"') && trimmed.endsWith('"')
          ? trimmed.slice(1, -1)
          : trimmed;
        this.addDictionary(encoder.encode(unquoted), 1);
      }
    }
  }

  /** Number of dictionary entries. */
  get dictionarySize(): number {
    return this.dictionary.length;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

type MutatorFn = (
  input: Uint8Array,
  maxSize: number,
  corpus: ReadonlyArray<FuzzInput>,
) => Uint8Array;

function cloneBytes(data: Uint8Array): Uint8Array {
  const copy = new Uint8Array(data.length);
  copy.set(data);
  return copy;
}

function splitByDelimiters(data: Uint8Array, delimiters: number[]): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  let start = 0;
  for (let i = 0; i < data.length; i++) {
    if (delimiters.includes(data[i]!)) {
      chunks.push(data.slice(start, i + 1));
      start = i + 1;
    }
  }
  if (start < data.length) {
    chunks.push(data.slice(start));
  }
  return chunks;
}

function joinChunks(chunks: Uint8Array[], maxSize: number): Uint8Array {
  let totalLen = 0;
  for (const c of chunks) totalLen += c.length;
  totalLen = Math.min(totalLen, maxSize);

  const buf = new Uint8Array(totalLen);
  let offset = 0;
  for (const c of chunks) {
    const len = Math.min(c.length, totalLen - offset);
    if (len <= 0) break;
    buf.set(c.subarray(0, len), offset);
    offset += len;
  }
  return buf;
}

function tokenize(text: string): string[] {
  // Split into meaningful tokens: words, numbers, symbols, whitespace
  return text.match(/\d+\.\d+|\d+|[a-zA-Z_]\w*|[^\s\w]|\s+/g) ?? [text];
}
