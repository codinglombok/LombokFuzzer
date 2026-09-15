/**
 * LombokFuzzer — Protocol Fuzzer
 *
 * Generates and mutates protocol messages for network fuzzing. Each protocol
 * module understands the wire format and can produce both valid and malformed
 * messages targeting parser bugs.
 *
 * Supported: HTTP/1.1, HTTP/2, DNS, TLS, gRPC, MQTT, WebSocket, USB, BLE
 *
 * @license Apache-2.0
 */
import type { PRNG } from '../utils/prng.js';
export interface ProtocolMessage {
    protocol: string;
    data: Uint8Array;
    metadata: Record<string, string>;
}
export interface ProtocolFuzzerModule {
    readonly name: string;
    generate(prng: PRNG): ProtocolMessage;
    mutate(msg: ProtocolMessage, prng: PRNG): ProtocolMessage;
}
export declare class HttpFuzzer implements ProtocolFuzzerModule {
    readonly name = "HTTP";
    private readonly methods;
    private readonly headers;
    private readonly attackPayloads;
    generate(prng: PRNG): ProtocolMessage;
    mutate(msg: ProtocolMessage, prng: PRNG): ProtocolMessage;
    private genPath;
    private genHost;
    private genHeaderValue;
    private genBody;
}
export declare class DnsFuzzer implements ProtocolFuzzerModule {
    readonly name = "DNS";
    generate(prng: PRNG): ProtocolMessage;
    mutate(msg: ProtocolMessage, prng: PRNG): ProtocolMessage;
}
export declare class WebSocketFuzzer implements ProtocolFuzzerModule {
    readonly name = "WebSocket";
    generate(prng: PRNG): ProtocolMessage;
    mutate(msg: ProtocolMessage, prng: PRNG): ProtocolMessage;
}
export declare class ProtocolFuzzerRegistry {
    private readonly modules;
    constructor();
    register(module: ProtocolFuzzerModule): void;
    get(name: string): ProtocolFuzzerModule | undefined;
    list(): string[];
}
//# sourceMappingURL=fuzzer.d.ts.map