"use strict";
/**
 * LombokFuzzer — Generator Engine
 *
 * Input generation strategies: random, grammar-based, protocol-template,
 * and model-guided. Used in Generation and Hybrid fuzz modes as the
 * counterpart to mutation-based input creation.
 *
 * @license Apache-2.0
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.GeneratorEngine = exports.GeneratorKind = void 0;
const hash_js_1 = require("../utils/hash.js");
const engine_js_1 = require("../grammar/engine.js");
// ─── Types ──────────────────────────────────────────────────────────────────
/** Identifies which generator produced an input. */
var GeneratorKind;
(function (GeneratorKind) {
    GeneratorKind["Random"] = "random";
    GeneratorKind["Grammar"] = "grammar";
    GeneratorKind["ProtocolTemplate"] = "protocol_template";
    GeneratorKind["ModelGuided"] = "model_guided";
    GeneratorKind["Dictionary"] = "dictionary";
    GeneratorKind["Custom"] = "custom";
})(GeneratorKind || (exports.GeneratorKind = GeneratorKind = {}));
// ─── Generator Engine ───────────────────────────────────────────────────────
class GeneratorEngine {
    config;
    prng;
    grammarEngine;
    history;
    recentCapacity = 64;
    constructor(config, prng) {
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
        this.grammarEngine = new engine_js_1.GrammarEngine(prng);
        this.history = {
            totalGenerated: 0,
            coverageHits: 0,
            crashHits: 0,
            recentInputs: [],
        };
    }
    /** Generate one input, cycling through enabled generators. */
    generate() {
        const kinds = this.config.kinds;
        if (kinds.length === 0) {
            return this.generateRandom();
        }
        // Round-robin with weighted randomness
        const kind = this.prng.pick(kinds);
        let result;
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
    toFuzzInput(result) {
        const hash = (0, hash_js_1.fnv1a64)(result.data);
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
                ...(result.grammarName ? [['grammar', result.grammarName]] : []),
                ...(result.protocolName ? [['protocol', result.protocolName]] : []),
            ]),
        };
    }
    /** Feedback: an input led to new coverage. */
    recordCoverageHit() {
        this.history.coverageHits++;
    }
    /** Feedback: an input led to a crash. */
    recordCrashHit() {
        this.history.crashHits++;
    }
    /** Get current generation stats. */
    get stats() {
        return this.history;
    }
    /** Register a grammar for grammar-based generation. */
    addGrammar(name, grammar) {
        this.config.grammars.set(name, grammar);
    }
    /** Register a protocol template. */
    addProtocolTemplate(name, templates) {
        this.config.protocolTemplates.set(name, templates);
    }
    // ─── Private generators ─────────────────────────────────────────────────
    generateRandom() {
        const size = this.prng.nextRange(this.config.maxSize - this.config.minSize + 1) + this.config.minSize;
        return {
            data: this.prng.randomBytes(size),
            kind: GeneratorKind.Random,
        };
    }
    generateGrammar() {
        const names = Array.from(this.config.grammars.keys());
        if (names.length === 0)
            return this.generateRandom();
        const name = this.prng.pick(names);
        const grammar = this.config.grammars.get(name);
        if (!grammar)
            return this.generateRandom();
        const data = this.grammarEngine.generate(grammar);
        return {
            data,
            kind: GeneratorKind.Grammar,
            grammarName: name,
        };
    }
    generateProtocolTemplate() {
        const names = Array.from(this.config.protocolTemplates.keys());
        if (names.length === 0)
            return this.generateRandom();
        const name = this.prng.pick(names);
        const templates = this.config.protocolTemplates.get(name);
        if (!templates || templates.length === 0)
            return this.generateRandom();
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
    generateModelGuided() {
        if (!this.config.modelCallback)
            return this.generateRandom();
        try {
            const data = this.config.modelCallback(this.history);
            return { data, kind: GeneratorKind.ModelGuided };
        }
        catch {
            return this.generateRandom();
        }
    }
    generateDictionary() {
        const tokens = this.config.dictionaryTokens;
        if (tokens.length === 0)
            return this.generateRandom();
        // Concatenate 1–8 random dictionary tokens
        const count = this.prng.nextRange(8) + 1;
        const parts = [];
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
            if (offset >= data.length)
                break;
        }
        return { data: data.subarray(0, offset), kind: GeneratorKind.Dictionary };
    }
    generateCustom() {
        if (!this.config.customGenerator)
            return this.generateRandom();
        try {
            const data = this.config.customGenerator(this.prng, {
                config: {}, // Placeholder — wired by FuzzEngine
                history: this.history,
                grammarEngine: this.grammarEngine,
            });
            return { data, kind: GeneratorKind.Custom };
        }
        catch {
            return this.generateRandom();
        }
    }
}
exports.GeneratorEngine = GeneratorEngine;
//# sourceMappingURL=engine.js.map