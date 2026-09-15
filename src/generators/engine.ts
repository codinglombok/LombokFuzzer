/**
 * LombokFuzzer — Generator Engine
 *
 * Input generation strategies: random, grammar-based, protocol-template,
 * and model-guided. Used in Generation and Hybrid fuzz modes as the
 * counterpart to mutation-based input creation.
 *
 * @license Apache-2.0
 */

import type { FuzzInput, FuzzConfig } from '../core/types.js';
import { PRNG } from '../utils/prng.js';
import { fnv1a64 } from '../utils/hash.js';
import { GrammarEngine } from '../grammar/engine.js';
import type { Grammar } from '../grammar/engine.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** Identifies which generator produced an input. */
export enum GeneratorKind {
  Random = 'random',
  Grammar = 'grammar',
  ProtocolTemplate = 'protocol_template',
  ModelGuided = 'model_guided',
  Dictionary = 'dictionary',
  Custom = 'custom',
}

/** Configuration for the generator subsystem. */
export interface GeneratorConfig {
  /** Which generators to enable (order = priority). */
  kinds: GeneratorKind[];
  /** Grammar definitions (key = name). */
  grammars: Map<string, Grammar>;
  /** Protocol templates (key = protocol name, value = template bytes). */
  protocolTemplates: Map<string, Uint8Array[]>;
  /** Model-guided callback (returns candidate bytes from an external model). */
  modelCallback?: (history: GenerationHistory) => Uint8Array;
  /** Dictionary tokens for dictionary-based generation. */
  dictionaryTokens: Uint8Array[];
  /** Custom generator function. */
  customGenerator?: (prng: PRNG, context: GenerationContext) => Uint8Array;
  /** Min input size. */
  minSize: number;
  /** Max input size. */
  maxSize: number;
}

/** Tracks what the generator has produced so far (for model-guided). */
export interface GenerationHistory {
  /** Total inputs generated. */
  totalGenerated: number;
  /** Inputs that led to new coverage. */
  coverageHits: number;
  /** Inputs that led to crashes. */
  crashHits: number;
  /** Last N generated inputs (ring buffer). */
  recentInputs: Uint8Array[];
}

/** Context available to custom generators. */
export interface GenerationContext {
  /** Campaign config. */
  config: Readonly<FuzzConfig>;
  /** Current generation history. */
  history: Readonly<GenerationHistory>;
  /** Available grammar engine. */
  grammarEngine: GrammarEngine;
}

/** Result of one generation call. */
export interface GenerationResult {
  /** Generated raw bytes. */
  data: Uint8Array;
  /** Which generator produced it. */
  kind: GeneratorKind;
  /** Grammar name (if grammar-based). */
  grammarName?: string;
  /** Protocol name (if template-based). */
  protocolName?: string;
}

// ─── Generator Engine ───────────────────────────────────────────────────────

export class GeneratorEngine {
  readonly config: GeneratorConfig;
  private readonly prng: PRNG;
  private readonly grammarEngine: GrammarEngine;
  private readonly history: GenerationHistory;
  private readonly recentCapacity = 64;

  constructor(config: Partial<GeneratorConfig>, prng: PRNG) {
    this.config = {
      kinds: config.kinds ?? [GeneratorKind.Random],
      grammars: config.grammars ?? new Map(),
      protocolTemplates: config.protocolTemplates ?? new Map(),
      modelCallback: config.modelCallback,
      dictionaryTokens: config.dictionaryTokens ?? [],
      customGenerator: config.customGenerator,
      minSize: config.minSize ?? 1,
      maxSize: config.maxSize ?? 4096,
    };
    this.prng = prng;
    this.grammarEngine = new GrammarEngine(prng);
    this.history = {
      totalGenerated: 0,
      coverageHits: 0,
      crashHits: 0,
      recentInputs: [],
    };
  }

  /** Generate one input, cycling through enabled generators. */
  generate(): GenerationResult {
    const kinds = this.config.kinds;
    if (kinds.length === 0) {
      return this.generateRandom();
    }

    // Round-robin with weighted randomness
    const kind = this.prng.pick(kinds);
    let result: GenerationResult;

    switch (kind) {
      case GeneratorKind.Grammar:
        result = this.generateGrammar();
        break;
      case GeneratorKind.ProtocolTemplate:
        result = this.generateProtocolTemplate();
        break;
      case GeneratorKind.ModelGuided:
        result = this.generateModelGuided();
        break;
      case GeneratorKind.Dictionary:
        result = this.generateDictionary();
        break;
      case GeneratorKind.Custom:
        result = this.generateCustom();
        break;
      default:
        result = this.generateRandom();
    }

    // Track history
    this.history.totalGenerated++;
    this.history.recentInputs.push(result.data);
    if (this.history.recentInputs.length > this.recentCapacity) {
      this.history.recentInputs.shift();
    }

    return result;
  }

  /** Convert a GenerationResult into a FuzzInput. */
  toFuzzInput(result: GenerationResult): FuzzInput {
    const hash = fnv1a64(result.data);
    return {
      data: result.data,
      hash,
      lineage: [],
      depth: 0,
      energy: 1,
      executions: 0,
      createdAt: Date.now(),
      tags: new Map([
        ['generator', result.kind],
        ...(result.grammarName ? [['grammar', result.grammarName] as [string, string]] : []),
        ...(result.protocolName ? [['protocol', result.protocolName] as [string, string]] : []),
      ]),
    };
  }

  /** Feedback: an input led to new coverage. */
  recordCoverageHit(): void {
    this.history.coverageHits++;
  }

  /** Feedback: an input led to a crash. */
  recordCrashHit(): void {
    this.history.crashHits++;
  }

  /** Get current generation stats. */
  get stats(): Readonly<GenerationHistory> {
    return this.history;
  }

  /** Register a grammar for grammar-based generation. */
  addGrammar(name: string, grammar: Grammar): void {
    this.config.grammars.set(name, grammar);
  }

  /** Register a protocol template. */
  addProtocolTemplate(name: string, templates: Uint8Array[]): void {
    this.config.protocolTemplates.set(name, templates);
  }

  // ─── Private generators ─────────────────────────────────────────────────

  private generateRandom(): GenerationResult {
    const size = this.prng.nextRange(
      this.config.maxSize - this.config.minSize + 1,
    ) + this.config.minSize;
    return {
      data: this.prng.randomBytes(size),
      kind: GeneratorKind.Random,
    };
  }

  private generateGrammar(): GenerationResult {
    const names = Array.from(this.config.grammars.keys());
    if (names.length === 0) return this.generateRandom();

    const name = this.prng.pick(names);
    const grammar = this.config.grammars.get(name);
    if (!grammar) return this.generateRandom();
    const data = this.grammarEngine.generate(grammar);
    return {
      data,
      kind: GeneratorKind.Grammar,
      grammarName: name,
    };
  }

  private generateProtocolTemplate(): GenerationResult {
    const names = Array.from(this.config.protocolTemplates.keys());
    if (names.length === 0) return this.generateRandom();

    const name = this.prng.pick(names);
    const templates = this.config.protocolTemplates.get(name);
    if (!templates || templates.length === 0) return this.generateRandom();

    // Pick a template and apply random mutations to variable slots
    const template = this.prng.pick(templates);
    const data = new Uint8Array(template);

    // Randomise ~10% of bytes
    const mutations = Math.max(1, Math.floor(data.length * 0.1));
    for (let i = 0; i < mutations; i++) {
      const pos = this.prng.nextRange(data.length);
      data[pos] = this.prng.nextRange(256);
    }

    return {
      data,
      kind: GeneratorKind.ProtocolTemplate,
      protocolName: name,
    };
  }

  private generateModelGuided(): GenerationResult {
    if (!this.config.modelCallback) return this.generateRandom();

    try {
      const data = this.config.modelCallback(this.history);
      return { data, kind: GeneratorKind.ModelGuided };
    } catch {
      return this.generateRandom();
    }
  }

  private generateDictionary(): GenerationResult {
    const tokens = this.config.dictionaryTokens;
    if (tokens.length === 0) return this.generateRandom();

    // Concatenate 1–8 random dictionary tokens
    const count = this.prng.nextRange(8) + 1;
    const parts: Uint8Array[] = [];
    let totalLen = 0;

    for (let i = 0; i < count && totalLen < this.config.maxSize; i++) {
      const token = this.prng.pick(tokens);
      parts.push(token);
      totalLen += token.length;
    }

    const data = new Uint8Array(Math.min(totalLen, this.config.maxSize));
    let offset = 0;
    for (const part of parts) {
      const len = Math.min(part.length, data.length - offset);
      data.set(part.subarray(0, len), offset);
      offset += len;
      if (offset >= data.length) break;
    }

    return { data: data.subarray(0, offset), kind: GeneratorKind.Dictionary };
  }

  private generateCustom(): GenerationResult {
    if (!this.config.customGenerator) return this.generateRandom();

    try {
      const data = this.config.customGenerator(this.prng, {
        config: {} as FuzzConfig, // Placeholder — wired by FuzzEngine
        history: this.history,
        grammarEngine: this.grammarEngine,
      });
      return { data, kind: GeneratorKind.Custom };
    } catch {
      return this.generateRandom();
    }
  }
}
