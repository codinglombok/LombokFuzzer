/**
 * LombokFuzzer — Typed Event Emitter
 *
 * Lightweight, zero-dependency event bus with typed events for the fuzz engine.
 * Supports sync and async handlers, once listeners, and wildcard capture.
 *
 * @license Apache-2.0
 */
import type { FuzzEvent, FuzzEventMap, FuzzEventHandler } from './types.js';
export declare class FuzzEventEmitter {
    private handlers;
    private wildcardHandlers;
    /** Register an event handler. */
    on<E extends FuzzEvent>(event: E, handler: FuzzEventHandler<FuzzEventMap[E]>): this;
    /** Register a one-shot handler (removed after first invocation). */
    once<E extends FuzzEvent>(event: E, handler: FuzzEventHandler<FuzzEventMap[E]>): this;
    /** Register a wildcard handler that receives all events. */
    onAny(handler: (event: string, data: unknown) => void): this;
    /** Remove a specific handler. */
    off<E extends FuzzEvent>(event: E, handler: FuzzEventHandler<FuzzEventMap[E]>): this;
    /** Remove all handlers for an event (or all events if no arg). */
    removeAllListeners(event?: FuzzEvent): this;
    /** Emit an event synchronously. */
    emit<E extends FuzzEvent>(event: E, data: FuzzEventMap[E]): boolean;
    /** Wait for a specific event (promise-based). */
    waitFor<E extends FuzzEvent>(event: E, timeoutMs?: number): Promise<FuzzEventMap[E]>;
    /** Return count of handlers for an event. */
    listenerCount(event: FuzzEvent): number;
}
//# sourceMappingURL=events.d.ts.map