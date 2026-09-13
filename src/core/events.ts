/**
 * LombokFuzzer — Typed Event Emitter
 *
 * Lightweight, zero-dependency event bus with typed events for the fuzz engine.
 * Supports sync and async handlers, once listeners, and wildcard capture.
 *
 * @license Apache-2.0
 */

import type { FuzzEvent, FuzzEventMap, FuzzEventHandler } from './types.js';

type Handler = { fn: FuzzEventHandler<any>; once: boolean };

export class FuzzEventEmitter {
  private handlers = new Map<string, Handler[]>();
  private wildcardHandlers: Handler[] = [];

  /** Register an event handler. */
  on<E extends FuzzEvent>(
    event: E,
    handler: FuzzEventHandler<FuzzEventMap[E]>,
  ): this {
    const list = this.handlers.get(event) ?? [];
    list.push({ fn: handler, once: false });
    this.handlers.set(event, list);
    return this;
  }

  /** Register a one-shot handler (removed after first invocation). */
  once<E extends FuzzEvent>(
    event: E,
    handler: FuzzEventHandler<FuzzEventMap[E]>,
  ): this {
    const list = this.handlers.get(event) ?? [];
    list.push({ fn: handler, once: true });
    this.handlers.set(event, list);
    return this;
  }

  /** Register a wildcard handler that receives all events. */
  onAny(handler: (event: string, data: unknown) => void): this {
    this.wildcardHandlers.push({ fn: handler as FuzzEventHandler, once: false });
    return this;
  }

  /** Remove a specific handler. */
  off<E extends FuzzEvent>(
    event: E,
    handler: FuzzEventHandler<FuzzEventMap[E]>,
  ): this {
    const list = this.handlers.get(event);
    if (list) {
      this.handlers.set(
        event,
        list.filter(h => h.fn !== handler),
      );
    }
    return this;
  }

  /** Remove all handlers for an event (or all events if no arg). */
  removeAllListeners(event?: FuzzEvent): this {
    if (event) {
      this.handlers.delete(event);
    } else {
      this.handlers.clear();
      this.wildcardHandlers = [];
    }
    return this;
  }

  /** Emit an event synchronously. */
  emit<E extends FuzzEvent>(event: E, data: FuzzEventMap[E]): boolean {
    const list = this.handlers.get(event);
    let handled = false;

    if (list) {
      const remaining: Handler[] = [];
      for (const h of list) {
        try {
          h.fn(data);
          handled = true;
        } catch {
          // Swallow handler errors — fuzzer must not crash from reporters
        }
        if (!h.once) remaining.push(h);
      }
      this.handlers.set(event, remaining);
    }

    // Wildcard
    const wcRemaining: Handler[] = [];
    for (const h of this.wildcardHandlers) {
      try {
        (h.fn as (event: string, data: unknown) => void)(event, data);
        handled = true;
      } catch {
        // Swallow
      }
      if (!h.once) wcRemaining.push(h);
    }
    this.wildcardHandlers = wcRemaining;

    return handled;
  }

  /** Wait for a specific event (promise-based). */
  waitFor<E extends FuzzEvent>(
    event: E,
    timeoutMs: number = 0,
  ): Promise<FuzzEventMap[E]> {
    return new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;

      const handler = (data: FuzzEventMap[E]) => {
        if (timer) clearTimeout(timer);
        resolve(data);
      };

      this.once(event, handler);

      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          this.off(event, handler);
          reject(new Error(`Timeout waiting for event: ${event}`));
        }, timeoutMs);
      }
    });
  }

  /** Return count of handlers for an event. */
  listenerCount(event: FuzzEvent): number {
    return (this.handlers.get(event)?.length ?? 0) + this.wildcardHandlers.length;
  }
}
