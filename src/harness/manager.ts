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

import type {
  FuzzInput,
  ExecutionResult,
  HarnessConfig,
  HarnessMode,
} from '../core/types.js';

// ─── Harness Interface ──────────────────────────────────────────────────────

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

// ─── InProcess Harness ──────────────────────────────────────────────────────

export class InProcessHarness implements Harness {
  readonly kind = 'in_process' as HarnessMode;
  private readonly targetFn: (data: Uint8Array) => void;


  constructor(targetFn: (data: Uint8Array) => void, _timeoutMs = 5000) {
    this.targetFn = targetFn;

  }

  async init(): Promise<void> { /* no-op */ }

  async execute(input: FuzzInput): Promise<ExecutionResult> {
    const start = hrtimeUs();
    let crashed = false;
    let exitCode = 0;
    let stderr: string | undefined;

    try {
      this.targetFn(input.data);
    } catch (err: unknown) {
      crashed = true;
      exitCode = 1;
      if (err instanceof Error) {
        stderr = `${err.name}: ${err.message}\n${err.stack ?? ''}`;
      } else {
        stderr = String(err);
      }
    }

    const durationUs = hrtimeUs() - start;
    input.executions++;

    return {
      input,
      crashed,
      newCoverage: false,   // Coverage is merged externally by the engine
      newEdges: [],
      durationUs,
      peakMemoryBytes: -1,
      exitCode,
      signal: 0,
      stderr,
    };
  }

  async destroy(): Promise<void> { /* no-op */ }
}

// ─── ForkServer Harness ─────────────────────────────────────────────────────

/**
 * Fork-server harness — spawns a persistent child process and sends inputs
 * via stdin (AFL-compatible). The child is forked once; subsequent inputs
 * reuse the warm process. Requires Node.js `child_process`.
 *
 * NOTE: Full implementation requires native IPC / shared-memory bitmap.
 * This is a structural scaffold; the IPC protocol will be finished in v0.3.0.
 */
export class ForkServerHarness implements Harness {
  readonly kind = 'fork_server' as HarnessMode;
  private readonly binaryPath: string;
  private readonly args: string[];
  private readonly timeoutMs: number;
  private child: unknown = null; // ChildProcess — typed loosely for portability

  constructor(binaryPath: string, args: string[] = [], timeoutMs = 5000) {
    this.binaryPath = binaryPath;
    this.args = args;
    this.timeoutMs = timeoutMs;
  }

  async init(): Promise<void> {
    // Lazy-import child_process (Node-only)
    try {
      const cp = await import('child_process');
      this.child = cp.spawn(this.binaryPath, this.args, {
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch {
      throw new Error(
        `ForkServerHarness: could not spawn "${this.binaryPath}". ` +
        'Ensure the binary exists and child_process is available.',
      );
    }
  }

  async execute(input: FuzzInput): Promise<ExecutionResult> {
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

  async destroy(): Promise<void> {
    if (this.child && typeof (this.child as any).kill === 'function') {
      (this.child as any).kill('SIGKILL');
    }
    this.child = null;
  }

  private async runChild(data: Uint8Array): Promise<{
    exitCode: number; signal: number; stderr?: string;
  }> {
    return new Promise((resolve) => {
      const child = this.child as any;
      if (!child || !child.stdin) {
        resolve({ exitCode: -1, signal: 0, stderr: 'no child process' });
        return;
      }

      let stderr = '';
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        resolve({ exitCode: -1, signal: 9, stderr: 'timeout' });
      }, this.timeoutMs);

      child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
      child.once('exit', (code: number | null, sig: string | null) => {
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

// ─── Network Harness ────────────────────────────────────────────────────────

/**
 * Network harness — sends input over TCP to a target service and
 * checks for crashes by reading the response (or detecting a
 * connection reset / timeout).
 */
export class NetworkHarness implements Harness {
  readonly kind = 'network' as HarnessMode;
  private readonly host: string;
  private readonly port: number;
  private readonly timeoutMs: number;
  private readonly protocol: 'tcp' | 'udp';

  constructor(target: string, timeoutMs = 5000, protocol: 'tcp' | 'udp' = 'tcp') {
    const parts = target.split(':');
    const host = parts[0] ?? 'localhost';
    const portStr = parts[1] ?? '0';
    this.host = host;
    this.port = parseInt(portStr, 10);
    this.timeoutMs = timeoutMs;
    this.protocol = protocol;
  }

  async init(): Promise<void> { /* connection is per-execution */ }

  async execute(input: FuzzInput): Promise<ExecutionResult> {
    const start = hrtimeUs();
    let crashed = false;
    let exitCode = 0;
    let stderr: string | undefined;

    try {
      if (this.protocol === 'tcp') {
        await this.sendTcp(input.data);
      } else {
        await this.sendUdp(input.data);
      }
    } catch (err: unknown) {
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

  async destroy(): Promise<void> { /* no persistent connection */ }

  private async sendTcp(data: Uint8Array): Promise<Buffer> {
    const net = await import('net');
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: this.host, port: this.port }, () => {
        socket.write(data);
      });
      const chunks: Buffer[] = [];
      socket.setTimeout(this.timeoutMs);
      socket.on('data', (chunk) => chunks.push(chunk));
      socket.on('end', () => { resolve(Buffer.concat(chunks)); });
      socket.on('timeout', () => { socket.destroy(); reject(new Error('timeout')); });
      socket.on('error', reject);
    });
  }

  private async sendUdp(data: Uint8Array): Promise<void> {
    const dgram = await import('dgram');
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      socket.send(data, this.port, this.host, (err) => {
        socket.close();
        if (err) reject(err); else resolve();
      });
    });
  }
}

// ─── WASM Harness ───────────────────────────────────────────────────────────

/**
 * WASM harness — instantiates a WASM module and calls its exported fuzz
 * target with the input written into linear memory.
 */
export class WasmHarness implements Harness {
  readonly kind = 'wasm' as HarnessMode;
  private readonly wasmBytes: Uint8Array;
  private readonly entryPoint: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private instance: any = null;

  constructor(wasmBytes: Uint8Array, entryPoint = 'LLVMFuzzerTestOneInput') {
    this.wasmBytes = wasmBytes;
    this.entryPoint = entryPoint;
  }

  async init(): Promise<void> {
    const WA = (globalThis as any).WebAssembly;
    if (!WA) throw new Error('WebAssembly not available');
    const mod = await WA.compile(this.wasmBytes);
    this.instance = await WA.instantiate(mod, {
      env: {
        abort: () => { throw new Error('WASM abort'); },
      },
    });
  }

  async execute(input: FuzzInput): Promise<ExecutionResult> {
    if (!this.instance) throw new Error('WasmHarness not initialised');

    const start = hrtimeUs();
    let crashed = false;
    let exitCode = 0;
    let stderr: string | undefined;

    try {
      const memory = this.instance.exports.memory as any;
      const alloc = this.instance.exports.malloc as ((n: number) => number) | undefined;
      const target = this.instance.exports[this.entryPoint] as
        ((ptr: number, len: number) => number) | undefined;

      if (!target) {
        throw new Error(`WASM module has no export "${this.entryPoint}"`);
      }

      // Allocate input in linear memory
      let ptr: number;
      if (alloc) {
        ptr = alloc(input.data.length);
      } else {
        // Fallback: write at a fixed offset past the initial data
        ptr = 65536;
        if (memory.buffer.byteLength < ptr + input.data.length) {
          memory.grow(Math.ceil((ptr + input.data.length - memory.buffer.byteLength) / 65536));
        }
      }

      new Uint8Array(memory.buffer).set(input.data, ptr);
      target(ptr, input.data.length);
    } catch (err: unknown) {
      crashed = true;
      exitCode = 1;
      if (err instanceof Error) stderr = err.message;
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

  async destroy(): Promise<void> {
    this.instance = null;
  }
}

// ─── Harness Manager ────────────────────────────────────────────────────────

/**
 * Factory that creates the right harness from a `HarnessConfig`.
 */
export class HarnessManager {
  private harness: Harness | null = null;
  private readonly stats: HarnessStats = {
    totalExecutions: 0,
    totalCrashes: 0,
    totalTimeouts: 0,
    avgDurationUs: 0,
    peakDurationUs: 0,
  };
  private durationSum = 0;

  /** Create and initialise the harness from config. */
  async init(config: HarnessConfig): Promise<Harness> {
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
        this.harness = new ForkServerHarness(
          config.targetBinary,
          config.targetArgs ?? [],
        );
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
  async execute(input: FuzzInput): Promise<ExecutionResult> {
    if (!this.harness) throw new Error('HarnessManager not initialised');

    const result = await this.harness.execute(input);

    this.stats.totalExecutions++;
    this.durationSum += result.durationUs;
    this.stats.avgDurationUs = Math.round(this.durationSum / this.stats.totalExecutions);
    this.stats.peakDurationUs = Math.max(this.stats.peakDurationUs, result.durationUs);
    if (result.crashed) this.stats.totalCrashes++;
    if (result.durationUs > 5_000_000) this.stats.totalTimeouts++; // >5s

    return result;
  }

  /** Get current harness stats. */
  getStats(): Readonly<HarnessStats> {
    return this.stats;
  }

  /** Destroy the active harness. */
  async destroy(): Promise<void> {
    if (this.harness) {
      await this.harness.destroy();
      this.harness = null;
    }
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function hrtimeUs(): number {
  if (typeof performance !== 'undefined') {
    return Math.round(performance.now() * 1000);
  }
  const [sec, nsec] = process.hrtime();
  return sec * 1_000_000 + Math.round(nsec / 1000);
}

function signalToNumber(sig: string | null): number {
  if (!sig) return 0;
  const map: Record<string, number> = {
    SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5,
    SIGABRT: 6, SIGBUS: 7, SIGFPE: 8, SIGKILL: 9, SIGSEGV: 11,
    SIGTERM: 15,
  };
  return map[sig] ?? 0;
}
