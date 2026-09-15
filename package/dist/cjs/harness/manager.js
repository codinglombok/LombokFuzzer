"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.HarnessManager = exports.WasmHarness = exports.NetworkHarness = exports.ForkServerHarness = exports.InProcessHarness = void 0;
// ─── InProcess Harness ──────────────────────────────────────────────────────
class InProcessHarness {
    kind = 'in_process';
    targetFn;
    constructor(targetFn, _timeoutMs = 5000) {
        this.targetFn = targetFn;
    }
    async init() { }
    async execute(input) {
        const start = hrtimeUs();
        let crashed = false;
        let exitCode = 0;
        let stderr;
        try {
            this.targetFn(input.data);
        }
        catch (err) {
            crashed = true;
            exitCode = 1;
            if (err instanceof Error) {
                stderr = `${err.name}: ${err.message}\n${err.stack ?? ''}`;
            }
            else {
                stderr = String(err);
            }
        }
        const durationUs = hrtimeUs() - start;
        input.executions++;
        return {
            input,
            crashed,
            newCoverage: false, // Coverage is merged externally by the engine
            newEdges: [],
            durationUs,
            peakMemoryBytes: -1,
            exitCode,
            signal: 0,
            stderr,
        };
    }
    async destroy() { }
}
exports.InProcessHarness = InProcessHarness;
// ─── ForkServer Harness ─────────────────────────────────────────────────────
/**
 * Fork-server harness — spawns a persistent child process and sends inputs
 * via stdin (AFL-compatible). The child is forked once; subsequent inputs
 * reuse the warm process. Requires Node.js `child_process`.
 *
 * NOTE: Full implementation requires native IPC / shared-memory bitmap.
 * This is a structural scaffold; the IPC protocol will be finished in v0.3.0.
 */
class ForkServerHarness {
    kind = 'fork_server';
    binaryPath;
    args;
    timeoutMs;
    child = null; // ChildProcess — typed loosely for portability
    constructor(binaryPath, args = [], timeoutMs = 5000) {
        this.binaryPath = binaryPath;
        this.args = args;
        this.timeoutMs = timeoutMs;
    }
    async init() {
        // Lazy-import child_process (Node-only)
        try {
            const cp = await Promise.resolve().then(() => __importStar(require('child_process')));
            this.child = cp.spawn(this.binaryPath, this.args, {
                stdio: ['pipe', 'pipe', 'pipe'],
            });
        }
        catch {
            throw new Error(`ForkServerHarness: could not spawn "${this.binaryPath}". ` +
                'Ensure the binary exists and child_process is available.');
        }
    }
    async execute(input) {
        const start = hrtimeUs();
        // Write input to child's stdin, read exit status
        const result = await this.runChild(input.data);
        const durationUs = hrtimeUs() - start;
        input.executions++;
        return {
            input,
            crashed: result.exitCode !== 0,
            newCoverage: false,
            newEdges: [],
            durationUs,
            peakMemoryBytes: -1,
            exitCode: result.exitCode,
            signal: result.signal,
            stderr: result.stderr,
        };
    }
    async destroy() {
        if (this.child && typeof this.child.kill === 'function') {
            this.child.kill('SIGKILL');
        }
        this.child = null;
    }
    async runChild(data) {
        return new Promise((resolve) => {
            const child = this.child;
            if (!child || !child.stdin) {
                resolve({ exitCode: -1, signal: 0, stderr: 'no child process' });
                return;
            }
            let stderr = '';
            const timer = setTimeout(() => {
                child.kill('SIGKILL');
                resolve({ exitCode: -1, signal: 9, stderr: 'timeout' });
            }, this.timeoutMs);
            child.stderr?.on('data', (chunk) => { stderr += chunk.toString(); });
            child.once('exit', (code, sig) => {
                clearTimeout(timer);
                resolve({
                    exitCode: code ?? -1,
                    signal: signalToNumber(sig),
                    stderr: stderr || undefined,
                });
            });
            child.stdin.write(data);
            child.stdin.end();
        });
    }
}
exports.ForkServerHarness = ForkServerHarness;
// ─── Network Harness ────────────────────────────────────────────────────────
/**
 * Network harness — sends input over TCP to a target service and
 * checks for crashes by reading the response (or detecting a
 * connection reset / timeout).
 */
class NetworkHarness {
    kind = 'network';
    host;
    port;
    timeoutMs;
    protocol;
    constructor(target, timeoutMs = 5000, protocol = 'tcp') {
        const parts = target.split(':');
        const host = parts[0] ?? 'localhost';
        const portStr = parts[1] ?? '0';
        this.host = host;
        this.port = parseInt(portStr, 10);
        this.timeoutMs = timeoutMs;
        this.protocol = protocol;
    }
    async init() { }
    async execute(input) {
        const start = hrtimeUs();
        let crashed = false;
        let exitCode = 0;
        let stderr;
        try {
            if (this.protocol === 'tcp') {
                await this.sendTcp(input.data);
            }
            else {
                await this.sendUdp(input.data);
            }
        }
        catch (err) {
            crashed = true;
            exitCode = 1;
            if (err instanceof Error) {
                stderr = err.message;
                // Connection reset / ECONNREFUSED → likely crash
                if (err.message.includes('ECONNRESET') || err.message.includes('ECONNREFUSED')) {
                    crashed = true;
                }
            }
        }
        const durationUs = hrtimeUs() - start;
        input.executions++;
        return {
            input,
            crashed,
            newCoverage: false,
            newEdges: [],
            durationUs,
            peakMemoryBytes: -1,
            exitCode,
            signal: 0,
            stderr,
        };
    }
    async destroy() { }
    async sendTcp(data) {
        const net = await Promise.resolve().then(() => __importStar(require('net')));
        return new Promise((resolve, reject) => {
            const socket = net.createConnection({ host: this.host, port: this.port }, () => {
                socket.write(data);
            });
            const chunks = [];
            socket.setTimeout(this.timeoutMs);
            socket.on('data', (chunk) => chunks.push(chunk));
            socket.on('end', () => { resolve(Buffer.concat(chunks)); });
            socket.on('timeout', () => { socket.destroy(); reject(new Error('timeout')); });
            socket.on('error', reject);
        });
    }
    async sendUdp(data) {
        const dgram = await Promise.resolve().then(() => __importStar(require('dgram')));
        return new Promise((resolve, reject) => {
            const socket = dgram.createSocket('udp4');
            socket.send(data, this.port, this.host, (err) => {
                socket.close();
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
    }
}
exports.NetworkHarness = NetworkHarness;
// ─── WASM Harness ───────────────────────────────────────────────────────────
/**
 * WASM harness — instantiates a WASM module and calls its exported fuzz
 * target with the input written into linear memory.
 */
class WasmHarness {
    kind = 'wasm';
    wasmBytes;
    entryPoint;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    instance = null;
    constructor(wasmBytes, entryPoint = 'LLVMFuzzerTestOneInput') {
        this.wasmBytes = wasmBytes;
        this.entryPoint = entryPoint;
    }
    async init() {
        const WA = globalThis.WebAssembly;
        if (!WA)
            throw new Error('WebAssembly not available');
        const mod = await WA.compile(this.wasmBytes);
        this.instance = await WA.instantiate(mod, {
            env: {
                abort: () => { throw new Error('WASM abort'); },
            },
        });
    }
    async execute(input) {
        if (!this.instance)
            throw new Error('WasmHarness not initialised');
        const start = hrtimeUs();
        let crashed = false;
        let exitCode = 0;
        let stderr;
        try {
            const memory = this.instance.exports.memory;
            const alloc = this.instance.exports.malloc;
            const target = this.instance.exports[this.entryPoint];
            if (!target) {
                throw new Error(`WASM module has no export "${this.entryPoint}"`);
            }
            // Allocate input in linear memory
            let ptr;
            if (alloc) {
                ptr = alloc(input.data.length);
            }
            else {
                // Fallback: write at a fixed offset past the initial data
                ptr = 65536;
                if (memory.buffer.byteLength < ptr + input.data.length) {
                    memory.grow(Math.ceil((ptr + input.data.length - memory.buffer.byteLength) / 65536));
                }
            }
            new Uint8Array(memory.buffer).set(input.data, ptr);
            target(ptr, input.data.length);
        }
        catch (err) {
            crashed = true;
            exitCode = 1;
            if (err instanceof Error)
                stderr = err.message;
        }
        const durationUs = hrtimeUs() - start;
        input.executions++;
        return {
            input,
            crashed,
            newCoverage: false,
            newEdges: [],
            durationUs,
            peakMemoryBytes: -1,
            exitCode,
            signal: 0,
            stderr,
        };
    }
    async destroy() {
        this.instance = null;
    }
}
exports.WasmHarness = WasmHarness;
// ─── Harness Manager ────────────────────────────────────────────────────────
/**
 * Factory that creates the right harness from a `HarnessConfig`.
 */
class HarnessManager {
    harness = null;
    stats = {
        totalExecutions: 0,
        totalCrashes: 0,
        totalTimeouts: 0,
        avgDurationUs: 0,
        peakDurationUs: 0,
    };
    durationSum = 0;
    /** Create and initialise the harness from config. */
    async init(config) {
        const mode = config.mode;
        switch (mode) {
            case 'in_process':
                if (!config.targetFunction) {
                    throw new Error('InProcess harness requires targetFunction');
                }
                this.harness = new InProcessHarness(config.targetFunction);
                break;
            case 'fork_server':
                if (!config.targetBinary) {
                    throw new Error('ForkServer harness requires targetBinary');
                }
                this.harness = new ForkServerHarness(config.targetBinary, config.targetArgs ?? []);
                break;
            case 'network':
                if (!config.networkTarget) {
                    throw new Error('Network harness requires networkTarget (host:port)');
                }
                this.harness = new NetworkHarness(config.networkTarget);
                break;
            case 'wasm':
                if (!config.wasmModule) {
                    throw new Error('WASM harness requires wasmModule bytes');
                }
                this.harness = new WasmHarness(config.wasmModule);
                break;
            default:
                throw new Error(`Unsupported harness mode: ${mode}`);
        }
        await this.harness.init();
        return this.harness;
    }
    /** Execute input through the active harness and track stats. */
    async execute(input) {
        if (!this.harness)
            throw new Error('HarnessManager not initialised');
        const result = await this.harness.execute(input);
        this.stats.totalExecutions++;
        this.durationSum += result.durationUs;
        this.stats.avgDurationUs = Math.round(this.durationSum / this.stats.totalExecutions);
        this.stats.peakDurationUs = Math.max(this.stats.peakDurationUs, result.durationUs);
        if (result.crashed)
            this.stats.totalCrashes++;
        if (result.durationUs > 5_000_000)
            this.stats.totalTimeouts++; // >5s
        return result;
    }
    /** Get current harness stats. */
    getStats() {
        return this.stats;
    }
    /** Destroy the active harness. */
    async destroy() {
        if (this.harness) {
            await this.harness.destroy();
            this.harness = null;
        }
    }
}
exports.HarnessManager = HarnessManager;
// ─── Helpers ────────────────────────────────────────────────────────────────
function hrtimeUs() {
    if (typeof performance !== 'undefined') {
        return Math.round(performance.now() * 1000);
    }
    const [sec, nsec] = process.hrtime();
    return sec * 1_000_000 + Math.round(nsec / 1000);
}
function signalToNumber(sig) {
    if (!sig)
        return 0;
    const map = {
        SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5,
        SIGABRT: 6, SIGBUS: 7, SIGFPE: 8, SIGKILL: 9, SIGSEGV: 11,
        SIGTERM: 15,
    };
    return map[sig] ?? 0;
}
//# sourceMappingURL=manager.js.map