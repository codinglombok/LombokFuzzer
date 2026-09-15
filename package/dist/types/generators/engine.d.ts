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
import { GrammarEngine } from '../grammar/engine.js';
import type { Grammar } from '../grammar/engine.js';
/** Identifies which generator produced an input. */
export declare enum GeneratorKind {
    Random = "random",
    Grammar = "grammar",
    ProtocolTemplate = "protocol_template",
    ModelGuided = "model_guided",
    Dictionary = "dictionary",
    Custom = "custom"
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
export declare class GeneratorEngine {
    readonly config: GeneratorConfig;
    private readonly prng;
    private readonly grammarEngine;
    private readonly history;
    private readonly recentCapacity;
    constructor(config: Partial<GeneratorConfig>, prng: PRNG);
    /** Generate one input, cycling through enabled generators. */
    generate(): GenerationResult;
    /** Convert a GenerationResult into a FuzzInput. */
    toFuzzInput(result: GenerationResult): FuzzInput;
    /** Feedback: an input led to new coverage. */
    recordCoverageHit(): void;
    /** Feedback: an input led to a crash. */
    recordCrashHit(): void;
    /** Get current generation stats. */
    get stats(): Readonly<GenerationHistory>;
    /** Register a grammar for grammar-based generation. */
    addGrammar(name: string, grammar: Grammar): void;
    /** Register a protocol template. */
    addProtocolTemplate(name: string, templates: Uint8Array[]): void;
    private generateRandom;
    private generateGrammar;
    private generateProtocolTemplate;
    private generateModelGuided;
    private generateDictionary;
    private generateCustom;
}
//# sourceMappingURL=engine.d.ts.map