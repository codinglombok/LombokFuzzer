"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProtocolFuzzerRegistry = exports.WebSocketFuzzer = exports.DnsFuzzer = exports.HttpFuzzer = void 0;
// ─── HTTP Fuzzer ────────────────────────────────────────────────────────────
class HttpFuzzer {
    name = 'HTTP';
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD',
        'OPTIONS', 'TRACE', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL',
        'COPY', 'MOVE', 'LOCK', 'UNLOCK'];
    headers = [
        'Host', 'Content-Type', 'Content-Length', 'Accept', 'Authorization',
        'Cookie', 'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP',
        'Transfer-Encoding', 'Connection', 'Upgrade', 'Range',
        'If-Modified-Since', 'Cache-Control', 'Accept-Encoding',
    ];
    attackPayloads = [
        '%00', '%0a%0d', '%0d%0a', '../', '..\\', '..%2f',
        'javascript:', 'data:', 'file://', 'gopher://',
        '%7B%7B7*7%7D%7D', '${7*7}', '{{constructor.constructor("return this")()}}',
        "' OR '1'='1", '" OR "1"="1', "'; DROP TABLE users; --",
        '<script>alert(1)</script>', '<img onerror=alert(1) src=x>',
        '\r\nSet-Cookie: evil=true', '\r\nLocation: http://evil.com',
    ];
    generate(prng) {
        const method = prng.pick(this.methods);
        const path = this.genPath(prng);
        const version = prng.pick(['HTTP/1.0', 'HTTP/1.1', 'HTTP/2']);
        const headerCount = 1 + prng.nextRange(10);
        let request = `${method} ${path} ${version}\r\n`;
        request += `Host: ${this.genHost(prng)}\r\n`;
        for (let i = 0; i < headerCount; i++) {
            const name = prng.pick(this.headers);
            const value = this.genHeaderValue(name, prng);
            request += `${name}: ${value}\r\n`;
        }
        request += '\r\n';
        if (['POST', 'PUT', 'PATCH'].includes(method) && prng.nextBool(0.7)) {
            const body = this.genBody(prng);
            request += body;
        }
        return {
            protocol: 'HTTP',
            data: new TextEncoder().encode(request),
            metadata: { method, path, version },
        };
    }
    mutate(msg, prng) {
        let text = new TextDecoder().decode(msg.data);
        const mutation = prng.nextRange(8);
        switch (mutation) {
            case 0: // Inject attack payload in path
                text = text.replace(/ \/.+? /, ` /${prng.pick(this.attackPayloads)} `);
                break;
            case 1: // Duplicate headers
                {
                    const lines = text.split('\r\n');
                    if (lines.length > 2) {
                        const idx = 1 + prng.nextRange(lines.length - 2);
                        lines.splice(idx, 0, lines[idx]);
                    }
                    text = lines.join('\r\n');
                }
                break;
            case 2: // Huge header value
                text = text.replace(/: .+?\r\n/, `: ${'A'.repeat(8192)}\r\n`);
                break;
            case 3: // Invalid Content-Length
                text = text.replace(/Content-Length: \d+/, `Content-Length: ${prng.nextRange(999999)}`);
                break;
            case 4: // Request smuggling
                text += `\r\nTransfer-Encoding: chunked\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n`;
                break;
            case 5: // Null bytes
                text = text.replace(/Host:/, 'Host:\x00');
                break;
            case 6: // CRLF injection
                text = text.replace(/\r\n/, `\r\n${prng.pick(this.attackPayloads)}\r\n`);
                break;
            case 7: // Invalid method
                text = text.replace(/^[A-Z]+/, 'AAAA'.repeat(100));
                break;
        }
        return { ...msg, data: new TextEncoder().encode(text) };
    }
    genPath(prng) {
        const segments = 1 + prng.nextRange(5);
        const parts = ['/'];
        for (let i = 0; i < segments; i++) {
            const len = 1 + prng.nextRange(10);
            let seg = '';
            for (let j = 0; j < len; j++) {
                seg += String.fromCharCode(97 + prng.nextRange(26));
            }
            parts.push(seg);
        }
        return parts.join('/');
    }
    genHost(prng) {
        const len = 3 + prng.nextRange(10);
        let host = '';
        for (let i = 0; i < len; i++)
            host += String.fromCharCode(97 + prng.nextRange(26));
        return `${host}.com`;
    }
    genHeaderValue(name, prng) {
        const common = {
            'Content-Type': ['text/html', 'application/json', 'multipart/form-data', 'text/xml'],
            'Accept': ['*/*', 'text/html', 'application/json'],
            'Transfer-Encoding': ['chunked', 'identity', 'gzip, chunked'],
            'Connection': ['keep-alive', 'close', 'upgrade'],
        };
        if (common[name])
            return prng.pick(common[name]);
        const len = 1 + prng.nextRange(50);
        let val = '';
        for (let i = 0; i < len; i++)
            val += String.fromCharCode(32 + prng.nextRange(95));
        return val;
    }
    genBody(prng) {
        const bodyType = prng.nextRange(3);
        if (bodyType === 0)
            return `{"key":"${prng.pick(this.attackPayloads)}"}`;
        if (bodyType === 1)
            return `name=${prng.pick(this.attackPayloads)}&value=test`;
        const len = prng.nextRange(1024);
        let body = '';
        for (let i = 0; i < len; i++)
            body += String.fromCharCode(32 + prng.nextRange(95));
        return body;
    }
}
exports.HttpFuzzer = HttpFuzzer;
// ─── DNS Fuzzer ─────────────────────────────────────────────────────────────
class DnsFuzzer {
    name = 'DNS';
    generate(prng) {
        const buf = new Uint8Array(512);
        let offset = 0;
        // Transaction ID
        buf[offset++] = prng.nextRange(256);
        buf[offset++] = prng.nextRange(256);
        // Flags: standard query
        buf[offset++] = 0x01; // RD=1
        buf[offset++] = 0x00;
        // QDCOUNT = 1
        buf[offset++] = 0x00;
        buf[offset++] = 0x01;
        // ANCOUNT, NSCOUNT, ARCOUNT = 0
        for (let i = 0; i < 6; i++)
            buf[offset++] = 0x00;
        // Question: domain name
        const labels = 1 + prng.nextRange(4);
        for (let i = 0; i < labels; i++) {
            const len = 1 + prng.nextRange(15);
            buf[offset++] = len;
            for (let j = 0; j < len; j++) {
                buf[offset++] = 97 + prng.nextRange(26); // a-z
            }
        }
        buf[offset++] = 0x00; // root label
        // QTYPE
        const types = [1, 2, 5, 6, 15, 16, 28, 33, 35, 255]; // A, NS, CNAME, SOA, MX, TXT, AAAA, SRV, NAPTR, ANY
        const qtype = prng.pick(types);
        buf[offset++] = (qtype >> 8) & 0xFF;
        buf[offset++] = qtype & 0xFF;
        // QCLASS = IN
        buf[offset++] = 0x00;
        buf[offset++] = 0x01;
        return {
            protocol: 'DNS',
            data: buf.slice(0, offset),
            metadata: { qtype: String(qtype) },
        };
    }
    mutate(msg, prng) {
        const buf = new Uint8Array(msg.data);
        const mutation = prng.nextRange(6);
        switch (mutation) {
            case 0: // Corrupt label length (pointer loop)
                if (buf.length > 12)
                    buf[12] = 0xC0; // compression pointer
                break;
            case 1: // Oversized label
                if (buf.length > 12)
                    buf[12] = 64; // max label is 63
                break;
            case 2: // Invalid QTYPE
                if (buf.length >= 2) {
                    buf[buf.length - 3] = prng.nextRange(256);
                    buf[buf.length - 4] = prng.nextRange(256);
                }
                break;
            case 3: // Corrupt flags
                if (buf.length > 3) {
                    buf[2] = prng.nextRange(256);
                    buf[3] = prng.nextRange(256);
                }
                break;
            case 4: // Invalid count fields
                if (buf.length > 5)
                    buf[5] = 255;
                break;
            case 5: // Truncate
                return { ...msg, data: buf.slice(0, prng.nextRange(buf.length)) };
        }
        return { ...msg, data: buf };
    }
}
exports.DnsFuzzer = DnsFuzzer;
// ─── WebSocket Fuzzer ───────────────────────────────────────────────────────
class WebSocketFuzzer {
    name = 'WebSocket';
    generate(prng) {
        // Generate a WebSocket frame
        const opcodes = [0x0, 0x1, 0x2, 0x8, 0x9, 0xA]; // cont, text, binary, close, ping, pong
        const opcode = prng.pick(opcodes);
        const payloadLen = prng.nextRange(1024);
        const payload = new Uint8Array(payloadLen);
        prng.fillBytes(payload);
        // Frame header
        const fin = prng.nextBool(0.9) ? 0x80 : 0x00;
        const masked = prng.nextBool(0.5) ? 0x80 : 0x00;
        let header;
        if (payloadLen < 126) {
            header = [fin | opcode, masked | payloadLen];
        }
        else if (payloadLen < 65536) {
            header = [fin | opcode, masked | 126, (payloadLen >> 8) & 0xFF, payloadLen & 0xFF];
        }
        else {
            header = [fin | opcode, masked | 127, 0, 0, 0, 0,
                (payloadLen >> 24) & 0xFF, (payloadLen >> 16) & 0xFF,
                (payloadLen >> 8) & 0xFF, payloadLen & 0xFF];
        }
        let mask = [];
        if (masked) {
            mask = [prng.nextRange(256), prng.nextRange(256), prng.nextRange(256), prng.nextRange(256)];
            for (let i = 0; i < payload.length; i++) {
                payload[i] ^= mask[i % 4];
            }
        }
        const frame = new Uint8Array(header.length + mask.length + payload.length);
        frame.set(header, 0);
        if (mask.length > 0)
            frame.set(mask, header.length);
        frame.set(payload, header.length + mask.length);
        return {
            protocol: 'WebSocket',
            data: frame,
            metadata: { opcode: `0x${opcode.toString(16)}`, payloadLen: String(payloadLen) },
        };
    }
    mutate(msg, prng) {
        const buf = new Uint8Array(msg.data);
        const mutation = prng.nextRange(5);
        switch (mutation) {
            case 0: // Invalid opcode
                if (buf.length > 0)
                    buf[0] = (buf[0] & 0xF0) | prng.nextRange(16);
                break;
            case 1: // Wrong length
                if (buf.length > 1)
                    buf[1] = (buf[1] & 0x80) | prng.nextRange(128);
                break;
            case 2: // RSV bits set (reserved, should be 0)
                if (buf.length > 0)
                    buf[0] = buf[0] | 0x70;
                break;
            case 3: // Fragment control frame
                if (buf.length > 0)
                    buf[0] = buf[0] & ~0x80; // clear FIN on control frame
                break;
            case 4: // Truncate mid-payload
                return { ...msg, data: buf.slice(0, 2 + prng.nextRange(Math.max(1, buf.length - 2))) };
        }
        return { ...msg, data: buf };
    }
}
exports.WebSocketFuzzer = WebSocketFuzzer;
// ─── Registry ───────────────────────────────────────────────────────────────
class ProtocolFuzzerRegistry {
    modules = new Map();
    constructor() {
        this.register(new HttpFuzzer());
        this.register(new DnsFuzzer());
        this.register(new WebSocketFuzzer());
    }
    register(module) {
        this.modules.set(module.name, module);
    }
    get(name) {
        return this.modules.get(name);
    }
    list() {
        return [...this.modules.keys()];
    }
}
exports.ProtocolFuzzerRegistry = ProtocolFuzzerRegistry;
//# sourceMappingURL=fuzzer.js.map