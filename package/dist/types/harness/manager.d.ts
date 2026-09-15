/**
 * LombokFuzzer — Harness Manager
 *
 * Abstracts how a fuzz target is executed. Each harness implements
 * `execute(input)` → `ExecutionResult`. The manager picks the right
 * harness from `HarnessConfig.mode` and handles lifecycle (init/cleanup).
 *
 * Supported modes:
 *   - InProcess   — call a JS/TS function directly
 *   - ForkServer  — spawn a child process (AFL-style)
 *   - Network     — send input over TCP/UDP to a service
 *   - WASM        — run input inside a WASM sandbox
 *   - Hardware    — (delegated to HardwareFuzzer)
 *   - Mobile      — (delegated to MobileFuzzer, future)
 *
 * @license Apache-2.0
 */
import type { FuzzInput, ExecutionResult, HarnessConfig, HarnessMode } from '../core/types.js';
/** Any execution harness implements this contract. */
export interface Harness {
    /** Unique identifier for this harness type. */
    readonly kind: HarnessMode;
    /** Initialise the harness (start fork server, open socket, etc.). */
    init(): Promise<void>;
    /** Execute one input and return the result. */
    execute(input: FuzzInput): Promise<ExecutionResult>;
    /** Release resources (kill child, close socket). */
    destroy(): Promise<void>;
}
/** Statistics tracked per harness. */
export interface HarnessStats {
    totalExecutions: number;
    totalCrashes: number;
    totalTimeouts: number;
    avgDurationUs: number;
    peakDurationUs: number;
}
export declare class InProcessHarness implements Harness {
    readonly kind: HarnessMode;
    private readonly targetFn;
    constructor(targetFn: (data: Uint8Array) => void, _timeoutMs?: number);
    init(): Promise<void>;
    execute(input: FuzzInput): Promise<ExecutionResult>;
    destroy(): Promise<void>;
}
/**
 * Fork-server harness — spawns a persistent child process and sends inputs
 * via stdin (AFL-compatible). The child is forked once; subsequent inputs
 * reuse the warm process. Requires Node.js `child_process`.
 *
 * NOTE: Full implementation requires native IPC / shared-memory bitmap.
 * This is a structural scaffold; the IPC protocol will be finished in v0.3.0.
 */
export declare class ForkServerHarness implements Harness {
    readonly kind: HarnessMode;
    private readonly binaryPath;
    private readonly args;
    private readonly timeoutMs;
    private child;
    constructor(binaryPath: string, args?: string[], timeoutMs?: number);
    init(): Promise<void>;
    execute(input: FuzzInput): Promise<ExecutionResult>;
    destroy(): Promise<void>;
    private runChild;
}
/**
 * Network harness — sends input over TCP to a target service and
 * checks for crashes by reading the response (or detecting a
 * connection reset / timeout).
 */
export declare class NetworkHarness implements Harness {
    readonly kind: HarnessMode;
    private readonly host;
    private readonly port;
    private readonly timeoutMs;
    private readonly protocol;
    constructor(target: string, timeoutMs?: number, protocol?: 'tcp' | 'udp');
    init(): Promise<void>;
    execute(input: FuzzInput): Promise<ExecutionResult>;
    destroy(): Promise<void>;
    private sendTcp;
    private sendUdp;
}
/**
 * WASM harness — instantiates a WASM module and calls its exported fuzz
 * target with the input written into linear memory.
 */
export declare class WasmHarness implements Harness {
    readonly kind: HarnessMode;
    private readonly wasmBytes;
    private readonly entryPoint;
    private instance;
    constructor(wasmBytes: Uint8Array, entryPoint?: string);
    init(): Promise<void>;
    execute(input: FuzzInput): Promise<ExecutionResult>;
    destroy(): Promise<void>;
}
/**
 * Factory that creates the right harness from a `HarnessConfig`.
 */
export declare class HarnessManager {
    private harness;
    private readonly stats;
    private durationSum;
    /** Create and initialise the harness from config. */
    init(config: HarnessConfig): Promise<Harness>;
    /** Execute input through the active harness and track stats. */
    execute(input: FuzzInput): Promise<ExecutionResult>;
    /** Get current harness stats. */
    getStats(): Readonly<HarnessStats>;
    /** Destroy the active harness. */
    destroy(): Promise<void>;
}
//# sourceMappingURL=manager.d.ts.map