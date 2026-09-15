/**
 * LombokFuzzer — Mobile Fuzzing Module
 *
 * Provides harness adapters for fuzzing mobile applications:
 *   - Android via ADB (instrument, input injection, logcat crash capture)
 *   - iOS via XCUITest (XCTest automation, crash log parsing)
 *   - React Native bridge (JS → native boundary fuzzing)
 *
 * Each adapter implements the Harness interface so the FuzzEngine
 * can drive mobile targets with the same loop as in-process ones.
 *
 * @license Apache-2.0
 */
import { Severity, CrashCategory } from '../core/types.js';
// ─── Types ──────────────────────────────────────────────────────────────────
/** Supported mobile platforms. */
export var MobilePlatform;
(function (MobilePlatform) {
    MobilePlatform["Android"] = "android";
    MobilePlatform["IOS"] = "ios";
    MobilePlatform["ReactNative"] = "react_native";
})(MobilePlatform || (MobilePlatform = {}));
// ─── Android Harness ────────────────────────────────────────────────────────
export class AndroidHarness {
    kind = 'mobile';
    config;
    constructor(config) {
        this.config = {
            serial: config.serial ?? '',
            packageName: config.packageName,
            activityName: config.activityName ?? '.MainActivity',
            instrumentRunner: config.instrumentRunner,
            deviceInputDir: config.deviceInputDir ?? '/data/local/tmp/fuzz_input',
            timeoutMs: config.timeoutMs ?? 10_000,
            captureLogcat: config.captureLogcat ?? true,
            adbPath: config.adbPath ?? 'adb',
        };
    }
    async init() {
        // Verify ADB connectivity
        const result = await this.adb(['devices']);
        if (!result.includes(this.config.serial || 'device')) {
            throw new Error(`AndroidHarness: device "${this.config.serial || '(any)'}" not found. ` +
                'Ensure ADB is running and the device is connected.');
        }
        // Create input dir on device
        await this.adb(['shell', 'mkdir', '-p', this.config.deviceInputDir]);
    }
    async execute(input) {
        const start = hrtimeUs();
        // 1) Push input to device
        const inputPath = `${this.config.deviceInputDir}/input.bin`;
        await this.pushBytes(input.data, inputPath);
        // 2) Clear logcat
        if (this.config.captureLogcat) {
            await this.adb(['logcat', '-c']);
        }
        // 3) Launch the target with input path as intent extra
        const launchArgs = [
            'shell', 'am', 'start',
            '-n', `${this.config.packageName}/${this.config.activityName}`,
            '--es', 'fuzz_input', inputPath,
        ];
        if (this.config.instrumentRunner) {
            // Use instrumentation instead of activity start
            launchArgs.length = 0;
            launchArgs.push('shell', 'am', 'instrument', '-w', '-e', 'inputPath', inputPath, `${this.config.packageName}/${this.config.instrumentRunner}`);
        }
        await this.adb(launchArgs);
        // 4) Wait and capture logcat
        await sleep(Math.min(this.config.timeoutMs, 2000));
        let logcat = '';
        let crashed = false;
        let stderr;
        if (this.config.captureLogcat) {
            logcat = await this.adb(['logcat', '-d', '-s', 'AndroidRuntime:E', 'DEBUG:*']);
            const crashReport = this.parseLogcat(logcat);
            if (crashReport) {
                crashed = true;
                stderr = crashReport.raw;
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
            exitCode: crashed ? 1 : 0,
            signal: 0,
            stderr,
        };
    }
    async destroy() {
        // Force-stop the target app
        await this.adb(['shell', 'am', 'force-stop', this.config.packageName]).catch(() => { });
    }
    /** Generate ADB fuzzing commands for batch testing. */
    generateAdbCommands(inputs, count) {
        const commands = [];
        const n = Math.min(inputs.length, count);
        for (let i = 0; i < n; i++) {
            const path = `${this.config.deviceInputDir}/input_${i}.bin`;
            commands.push(`adb ${this.serialFlag()}push /tmp/input_${i}.bin ${path}`);
            commands.push(`adb ${this.serialFlag()}shell am start -n ` +
                `${this.config.packageName}/${this.config.activityName} --es fuzz_input ${path}`);
            commands.push(`adb ${this.serialFlag()}logcat -d -s AndroidRuntime:E`);
        }
        return commands;
    }
    /** Parse logcat output for crash indicators. */
    parseLogcat(logcat) {
        // Check for fatal exceptions
        if (!logcat.includes('FATAL EXCEPTION') && !logcat.includes('signal ') &&
            !logcat.includes('SIGSEGV') && !logcat.includes('SIGABRT')) {
            return null;
        }
        const frames = this.parseNativeFrames(logcat);
        let signal = 'UNKNOWN';
        const sigMatch = logcat.match(/signal\s+(\d+)\s*\((\w+)\)/);
        if (sigMatch?.[2])
            signal = sigMatch[2];
        if (logcat.includes('FATAL EXCEPTION'))
            signal = 'JAVA_EXCEPTION';
        const processMatch = logcat.match(/Process:\s*([\w.]+)/);
        const threadMatch = logcat.match(/Thread:\s*(\S+)/);
        return {
            raw: logcat.substring(0, 4096),
            signal,
            process: processMatch?.[1] ?? this.config.packageName,
            thread: threadMatch?.[1] ?? 'main',
            frames,
            category: signalToCwe(signal),
            severity: signal === 'SIGSEGV' || signal === 'SIGABRT' ? Severity.Critical : Severity.High,
        };
    }
    parseNativeFrames(text) {
        const frames = [];
        const re = /#\d+\s+pc\s+([0-9a-f]+)\s+(\S+)\s*(?:\((.+?)(?:\+(\S+))?\))?/g;
        let m;
        while ((m = re.exec(text)) !== null && frames.length < 32) {
            frames.push({
                address: m[1] ?? '0',
                library: m[2] ?? '?',
                symbol: m[3] ?? '<unknown>',
                offset: m[4] ?? '0',
            });
        }
        return frames;
    }
    serialFlag() {
        return this.config.serial ? `-s ${this.config.serial} ` : '';
    }
    async adb(args) {
        const fullArgs = this.config.serial
            ? ['-s', this.config.serial, ...args]
            : args;
        try {
            const cp = await import('child_process');
            return new Promise((resolve, reject) => {
                cp.execFile(this.config.adbPath, fullArgs, { timeout: this.config.timeoutMs }, (_err, stdout, _stderr) => {
                    if (_err)
                        reject(_err);
                    else
                        resolve(stdout);
                });
            });
        }
        catch {
            // Fallback: return empty (ADB not available in this environment)
            return '';
        }
    }
    async pushBytes(data, remotePath) {
        try {
            const fs = await import('fs');
            const os = await import('os');
            const path = await import('path');
            const tmpFile = path.join(os.tmpdir(), `lkfuzz_${Date.now()}.bin`);
            fs.writeFileSync(tmpFile, data);
            await this.adb(['push', tmpFile, remotePath]);
            fs.unlinkSync(tmpFile);
        }
        catch {
            // Non-critical in environments without fs
        }
    }
}
// ─── iOS Harness ────────────────────────────────────────────────────────────
export class IOSHarness {
    kind = 'mobile';
    config;
    constructor(config) {
        this.config = {
            udid: config.udid ?? 'booted',
            bundleId: config.bundleId,
            testRunnerBundle: config.testRunnerBundle,
            deviceInputDir: config.deviceInputDir ?? '/tmp/fuzz_input',
            timeoutMs: config.timeoutMs ?? 15_000,
            xcrunPath: config.xcrunPath ?? 'xcrun',
        };
    }
    async init() {
        const result = await this.simctl(['list', 'devices', 'booted']);
        if (!result.includes('Booted') && !result.includes(this.config.udid)) {
            throw new Error(`IOSHarness: simulator "${this.config.udid}" not booted. ` +
                'Run `xcrun simctl boot <UDID>` first.');
        }
    }
    async execute(input) {
        const start = hrtimeUs();
        // Push input to simulator
        const inputPath = `${this.config.deviceInputDir}/input.bin`;
        await this.pushToSimulator(input.data, inputPath);
        // Launch app with input
        await this.simctl([
            'launch', this.config.udid, this.config.bundleId,
            '--fuzz-input', inputPath,
        ]);
        await sleep(Math.min(this.config.timeoutMs, 3000));
        // Check for crashes
        const crashLog = await this.getLatestCrashLog();
        const crashed = crashLog !== null;
        const durationUs = hrtimeUs() - start;
        input.executions++;
        return {
            input,
            crashed,
            newCoverage: false,
            newEdges: [],
            durationUs,
            peakMemoryBytes: -1,
            exitCode: crashed ? 1 : 0,
            signal: 0,
            stderr: crashLog?.raw,
        };
    }
    async destroy() {
        await this.simctl(['terminate', this.config.udid, this.config.bundleId]).catch(() => { });
    }
    /** Parse an iOS crash log (.ips / .crash). */
    parseCrashLog(text) {
        if (!text.includes('Exception Type') && !text.includes('Crashed Thread')) {
            return null;
        }
        const sigMatch = text.match(/Exception Type:\s*(\w+)\s*\((\w+)\)/);
        const signal = sigMatch?.[2] ?? sigMatch?.[1] ?? 'UNKNOWN';
        const frames = [];
        const re = /^\d+\s+(\S+)\s+(0x[0-9a-f]+)\s+(.+?)(?:\s*\+\s*(\d+))?$/gm;
        let m;
        while ((m = re.exec(text)) !== null && frames.length < 32) {
            frames.push({
                library: m[1] ?? '?',
                address: m[2] ?? '0',
                symbol: m[3] ?? '<unknown>',
                offset: m[4] ?? '0',
            });
        }
        return {
            raw: text.substring(0, 4096),
            signal,
            process: this.config.bundleId,
            thread: 'main',
            frames,
            category: signalToCwe(signal),
            severity: Severity.Critical,
        };
    }
    async simctl(args) {
        try {
            const cp = await import('child_process');
            return new Promise((resolve, reject) => {
                cp.execFile(this.config.xcrunPath, ['simctl', ...args], { timeout: this.config.timeoutMs }, (_err, stdout) => {
                    if (_err)
                        reject(_err);
                    else
                        resolve(stdout);
                });
            });
        }
        catch {
            return '';
        }
    }
    async pushToSimulator(data, remotePath) {
        try {
            const fs = await import('fs');
            // For simulators, the file system is directly accessible
            const simDataPath = await this.simctl(['get_app_container', this.config.udid, this.config.bundleId, 'data']);
            if (simDataPath.trim()) {
                const fullPath = `${simDataPath.trim()}${remotePath}`;
                fs.mkdirSync(fullPath.substring(0, fullPath.lastIndexOf('/')), { recursive: true });
                fs.writeFileSync(fullPath, data);
            }
        }
        catch {
            // Non-critical
        }
    }
    async getLatestCrashLog() {
        try {
            const result = await this.simctl(['diagnose', '-b', '--no-archive']);
            return this.parseCrashLog(result);
        }
        catch {
            return null;
        }
    }
}
// ─── React Native Bridge Fuzzer ─────────────────────────────────────────────
/**
 * Fuzzes the JS ↔ native bridge of React Native apps. Sends malformed
 * messages to bridge modules (NativeModules) and monitors for crashes
 * in the native layer via logcat or crash logs.
 */
export class ReactNativeHarness {
    kind = 'mobile';
    config;
    constructor(config) {
        this.config = {
            platform: config.platform ?? 'android',
            metroUrl: config.metroUrl ?? 'http://localhost:8081',
            bridgeModule: config.bridgeModule,
            bridgeMethod: config.bridgeMethod,
            timeoutMs: config.timeoutMs ?? 10_000,
        };
    }
    async init() {
        // Verify Metro bundler is reachable
        try {
            const resp = await fetch(`${this.config.metroUrl}/status`);
            if (!resp.ok)
                throw new Error(`Metro returned ${resp.status}`);
        }
        catch {
            throw new Error(`ReactNativeHarness: Metro bundler not reachable at ${this.config.metroUrl}. ` +
                'Ensure the dev server is running.');
        }
    }
    async execute(input) {
        const start = hrtimeUs();
        let crashed = false;
        let stderr;
        try {
            // Send fuzz input as a bridge call
            const payload = this.buildBridgePayload(input.data);
            const resp = await fetch(`${this.config.metroUrl}/message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(this.config.timeoutMs),
            });
            if (!resp.ok) {
                crashed = true;
                stderr = `Bridge call returned ${resp.status}: ${await resp.text()}`;
            }
        }
        catch (err) {
            crashed = true;
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
            exitCode: crashed ? 1 : 0,
            signal: 0,
            stderr,
        };
    }
    async destroy() { }
    /** Generate bridge payloads for common RN fuzz scenarios. */
    generateBridgePayloads(count) {
        const payloads = [];
        const templates = [
            // Type confusion
            () => [null],
            () => [undefined],
            () => [NaN],
            () => [Infinity],
            () => [-0],
            () => [''],
            () => ['A'.repeat(65536)],
            () => [{}],
            () => [[]],
            () => [new Array(10000).fill(0)],
            // Prototype pollution probes
            () => [{ __proto__: { polluted: true } }],
            () => [{ constructor: { prototype: { polluted: true } } }],
            // Large numbers
            () => [Number.MAX_SAFE_INTEGER + 1],
            () => [Number.MIN_SAFE_INTEGER - 1],
            () => [2 ** 53],
            // Nested objects
            () => [buildDeepObject(100)],
            // Unicode edge cases
            () => ['\uD800'], // lone surrogate
            () => ['\u0000'], // null byte
            () => ['\uFEFF'], // BOM
        ];
        for (let i = 0; i < count; i++) {
            const templateFn = templates[i % templates.length];
            payloads.push({
                module: this.config.bridgeModule,
                method: this.config.bridgeMethod,
                args: templateFn(),
            });
        }
        return payloads;
    }
    buildBridgePayload(data) {
        // Attempt to parse input as JSON args, fallback to raw string
        let args;
        try {
            const text = new TextDecoder().decode(data);
            const parsed = JSON.parse(text);
            args = Array.isArray(parsed) ? parsed : [parsed];
        }
        catch {
            args = [new TextDecoder().decode(data)];
        }
        return {
            module: this.config.bridgeModule,
            method: this.config.bridgeMethod,
            args,
        };
    }
}
// ─── Mobile Fuzzer Facade ───────────────────────────────────────────────────
/**
 * High-level facade that picks the right mobile harness from config.
 */
export class MobileFuzzer {
    /** Create an Android harness. */
    static android(config) {
        return new AndroidHarness(config);
    }
    /** Create an iOS harness. */
    static ios(config) {
        return new IOSHarness(config);
    }
    /** Create a React Native bridge fuzzer. */
    static reactNative(config) {
        return new ReactNativeHarness(config);
    }
}
// ─── Helpers ────────────────────────────────────────────────────────────────
function hrtimeUs() {
    if (typeof performance !== 'undefined') {
        return Math.round(performance.now() * 1000);
    }
    const [sec, nsec] = process.hrtime();
    return sec * 1_000_000 + Math.round(nsec / 1000);
}
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
function signalToCwe(signal) {
    switch (signal) {
        case 'SIGSEGV': return CrashCategory.NullDeref;
        case 'SIGABRT': return CrashCategory.Assertion;
        case 'SIGBUS': return CrashCategory.BufferOverflow;
        case 'SIGFPE': return CrashCategory.DivisionByZero;
        case 'SIGILL': return CrashCategory.Unknown;
        case 'EXC_BAD_ACCESS': return CrashCategory.NullDeref;
        case 'EXC_BAD_INSTRUCTION': return CrashCategory.Unknown;
        case 'JAVA_EXCEPTION': return CrashCategory.Unknown;
        default: return CrashCategory.Unknown;
    }
}
function buildDeepObject(depth) {
    let obj = { value: 'leaf' };
    for (let i = 0; i < depth; i++) {
        obj = { nested: obj };
    }
    return obj;
}
//# sourceMappingURL=fuzzer.js.map