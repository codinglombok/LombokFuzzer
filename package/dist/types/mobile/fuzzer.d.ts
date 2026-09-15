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
import type { FuzzInput, ExecutionResult } from '../core/types.js';
import type { Harness } from '../harness/manager.js';
import { Severity, CrashCategory } from '../core/types.js';
/** Supported mobile platforms. */
export declare enum MobilePlatform {
    Android = "android",
    IOS = "ios",
    ReactNative = "react_native"
}
/** Android device/emulator configuration. */
export interface AndroidConfig {
    /** ADB device serial (empty = first available). */
    serial: string;
    /** Target app package name. */
    packageName: string;
    /** Target activity (for launch). */
    activityName: string;
    /** Instrumentation runner class. */
    instrumentRunner?: string;
    /** Path to push input files on device. */
    deviceInputDir: string;
    /** Timeout per execution in ms. */
    timeoutMs: number;
    /** Whether to capture logcat for crash detection. */
    captureLogcat: boolean;
    /** ADB binary path (default: 'adb'). */
    adbPath: string;
}
/** iOS device/simulator configuration. */
export interface IOSConfig {
    /** Simulator UDID or device identifier. */
    udid: string;
    /** Bundle identifier of the target app. */
    bundleId: string;
    /** XCUITest test runner bundle. */
    testRunnerBundle?: string;
    /** Path on device/sim to push inputs. */
    deviceInputDir: string;
    /** Timeout per execution in ms. */
    timeoutMs: number;
    /** Path to xcrun (default: 'xcrun'). */
    xcrunPath: string;
}
/** React Native bridge fuzzing configuration. */
export interface ReactNativeConfig {
    /** Platform the RN app runs on. */
    platform: 'android' | 'ios';
    /** Metro bundler URL (default: http://localhost:8081). */
    metroUrl: string;
    /** Bridge module name to fuzz. */
    bridgeModule: string;
    /** Method name on the bridge module. */
    bridgeMethod: string;
    /** Timeout per execution in ms. */
    timeoutMs: number;
}
/** Mobile crash report parsed from logcat / crash logs. */
export interface MobileCrashReport {
    /** Raw crash text. */
    raw: string;
    /** Parsed signal (SIGSEGV, SIGABRT, etc.). */
    signal: string;
    /** Process that crashed. */
    process: string;
    /** Thread name. */
    thread: string;
    /** Stack frames (best-effort). */
    frames: MobileStackFrame[];
    /** CWE classification. */
    category: CrashCategory;
    /** Severity assessment. */
    severity: Severity;
    /** Tombstone / crash log path on device. */
    logPath?: string;
}
/** Stack frame from a mobile crash. */
export interface MobileStackFrame {
    address: string;
    library: string;
    symbol: string;
    offset: string;
}
export declare class AndroidHarness implements Harness {
    readonly kind: any;
    readonly config: AndroidConfig;
    constructor(config: Partial<AndroidConfig> & {
        packageName: string;
    });
    init(): Promise<void>;
    execute(input: FuzzInput): Promise<ExecutionResult>;
    destroy(): Promise<void>;
    /** Generate ADB fuzzing commands for batch testing. */
    generateAdbCommands(inputs: Uint8Array[], count: number): string[];
    /** Parse logcat output for crash indicators. */
    parseLogcat(logcat: string): MobileCrashReport | null;
    private parseNativeFrames;
    private serialFlag;
    private adb;
    private pushBytes;
}
export declare class IOSHarness implements Harness {
    readonly kind: any;
    readonly config: IOSConfig;
    constructor(config: Partial<IOSConfig> & {
        bundleId: string;
    });
    init(): Promise<void>;
    execute(input: FuzzInput): Promise<ExecutionResult>;
    destroy(): Promise<void>;
    /** Parse an iOS crash log (.ips / .crash). */
    parseCrashLog(text: string): MobileCrashReport | null;
    private simctl;
    private pushToSimulator;
    private getLatestCrashLog;
}
/**
 * Fuzzes the JS ↔ native bridge of React Native apps. Sends malformed
 * messages to bridge modules (NativeModules) and monitors for crashes
 * in the native layer via logcat or crash logs.
 */
export declare class ReactNativeHarness implements Harness {
    readonly kind: any;
    readonly config: ReactNativeConfig;
    constructor(config: Partial<ReactNativeConfig> & {
        bridgeModule: string;
        bridgeMethod: string;
    });
    init(): Promise<void>;
    execute(input: FuzzInput): Promise<ExecutionResult>;
    destroy(): Promise<void>;
    /** Generate bridge payloads for common RN fuzz scenarios. */
    generateBridgePayloads(count: number): BridgePayload[];
    private buildBridgePayload;
}
/** A React Native bridge call payload. */
export interface BridgePayload {
    module: string;
    method: string;
    args: unknown[];
}
/**
 * High-level facade that picks the right mobile harness from config.
 */
export declare class MobileFuzzer {
    /** Create an Android harness. */
    static android(config: Partial<AndroidConfig> & {
        packageName: string;
    }): AndroidHarness;
    /** Create an iOS harness. */
    static ios(config: Partial<IOSConfig> & {
        bundleId: string;
    }): IOSHarness;
    /** Create a React Native bridge fuzzer. */
    static reactNative(config: Partial<ReactNativeConfig> & {
        bridgeModule: string;
        bridgeMethod: string;
    }): ReactNativeHarness;
}
//# sourceMappingURL=fuzzer.d.ts.map