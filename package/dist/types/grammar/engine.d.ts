/**
 * LombokFuzzer — Grammar Engine
 *
 * Grammar-based input generation supporting ABNF, PEG, JSON Schema, and
 * custom DSL grammars. Generates syntactically valid inputs with targeted
 * semantic mutations.
 *
 * @license Apache-2.0
 */
import type { PRNG } from '../utils/prng.js';
export declare enum NodeKind {
    Literal = "literal",
    CharRange = "char_range",
    Sequence = "sequence",
    Alternative = "alternative",
    Repeat = "repeat",
    Optional = "optional",
    Reference = "reference"
}
export interface GrammarNode {
    kind: NodeKind;
    value?: string;
    children?: GrammarNode[];
    min?: number;
    max?: number;
    name?: string;
    weight?: number;
}
export interface Grammar {
    name: string;
    rules: Map<string, GrammarNode>;
    startRule: string;
}
export declare class GrammarEngine {
    private readonly prng;
    private readonly maxDepth;
    private readonly maxLength;
    constructor(prng: PRNG, maxDepth?: number, maxLength?: number);
    /** Generate an input from a grammar. */
    generate(grammar: Grammar): Uint8Array;
    /** Expand a grammar node into a string. */
    private expand;
    /** Mutate a generated input while preserving grammar structure. */
    mutateGrammarInput(input: string, grammar: Grammar): string;
    /** Build a JSON grammar. */
    static jsonGrammar(): Grammar;
    /** Build an HTTP request grammar. */
    static httpRequestGrammar(): Grammar;
    /** Build an SQL query grammar. */
    static sqlGrammar(): Grammar;
}
//# sourceMappingURL=engine.d.ts.map