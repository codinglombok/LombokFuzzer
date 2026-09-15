/**
 * LombokFuzzer — Typed Event Emitter
 *
 * Lightweight, zero-dependency event bus with typed events for the fuzz engine.
 * Supports sync and async handlers, once listeners, and wildcard capture.
 *
 * @license Apache-2.0
 */
export class FuzzEventEmitter {
    handlers = new Map();
    wildcardHandlers = [];
    /** Register an event handler. */
    on(event, handler) {
        const list = this.handlers.get(event) ?? [];
        list.push({ fn: handler, once: false });
        this.handlers.set(event, list);
        return this;
    }
    /** Register a one-shot handler (removed after first invocation). */
    once(event, handler) {
        const list = this.handlers.get(event) ?? [];
        list.push({ fn: handler, once: true });
        this.handlers.set(event, list);
        return this;
    }
    /** Register a wildcard handler that receives all events. */
    onAny(handler) {
        this.wildcardHandlers.push({ fn: handler, once: false });
        return this;
    }
    /** Remove a specific handler. */
    off(event, handler) {
        const list = this.handlers.get(event);
        if (list) {
            this.handlers.set(event, list.filter(h => h.fn !== handler));
        }
        return this;
    }
    /** Remove all handlers for an event (or all events if no arg). */
    removeAllListeners(event) {
        if (event) {
            this.handlers.delete(event);
        }
        else {
            this.handlers.clear();
            this.wildcardHandlers = [];
        }
        return this;
    }
    /** Emit an event synchronously. */
    emit(event, data) {
        const list = this.handlers.get(event);
        let handled = false;
        if (list) {
            const remaining = [];
            for (const h of list) {
                try {
                    h.fn(data);
                    handled = true;
                }
                catch {
                    // Swallow handler errors — fuzzer must not crash from reporters
                }
                if (!h.once)
                    remaining.push(h);
            }
            this.handlers.set(event, remaining);
        }
        // Wildcard
        const wcRemaining = [];
        for (const h of this.wildcardHandlers) {
            try {
                h.fn(event, data);
                handled = true;
            }
            catch {
                // Swallow
            }
            if (!h.once)
                wcRemaining.push(h);
        }
        this.wildcardHandlers = wcRemaining;
        return handled;
    }
    /** Wait for a specific event (promise-based). */
    waitFor(event, timeoutMs = 0) {
        return new Promise((resolve, reject) => {
            let timer;
            const handler = (data) => {
                if (timer)
                    clearTimeout(timer);
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
    listenerCount(event) {
        return (this.handlers.get(event)?.length ?? 0) + this.wildcardHandlers.length;
    }
}
//# sourceMappingURL=events.js.map