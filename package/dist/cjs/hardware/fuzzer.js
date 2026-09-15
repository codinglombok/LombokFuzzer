"use strict";
/**
 * LombokFuzzer — Hardware / Firmware Fuzzer
 *
 * Fuzz firmware and hardware interfaces: JTAG, SWD, UART, SPI, I2C, USB.
 * Generates malformed command sequences, boundary-value register writes,
 * and timing-attack probes.
 *
 * Designed for use with debug probes (J-Link, ST-Link, FTDI) but works
 * in simulation mode for CI testing.
 *
 * @license Apache-2.0
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.HardwareFuzzer = exports.HWInterface = void 0;
// ─── Types ──────────────────────────────────────────────────────────────────
var HWInterface;
(function (HWInterface) {
    HWInterface["JTAG"] = "jtag";
    HWInterface["SWD"] = "swd";
    HWInterface["UART"] = "uart";
    HWInterface["SPI"] = "spi";
    HWInterface["I2C"] = "i2c";
    HWInterface["USB"] = "usb";
})(HWInterface || (exports.HWInterface = HWInterface = {}));
// ─── Hardware Fuzzer ────────────────────────────────────────────────────────
class HardwareFuzzer {
    prng;
    findings = [];
    constructor(prng) {
        this.prng = prng;
    }
    /** Generate fuzz commands for a hardware target. */
    generateCommands(target, count = 100) {
        const commands = [];
        for (let i = 0; i < count; i++) {
            switch (target.interface) {
                case HWInterface.UART:
                    commands.push(this.fuzzUART(target));
                    break;
                case HWInterface.SPI:
                    commands.push(this.fuzzSPI(target));
                    break;
                case HWInterface.I2C:
                    commands.push(this.fuzzI2C(target));
                    break;
                case HWInterface.USB:
                    commands.push(this.fuzzUSB());
                    break;
                case HWInterface.JTAG:
                case HWInterface.SWD:
                    commands.push(this.fuzzDebugPort(target));
                    break;
            }
        }
        return commands;
    }
    /** Generate register fuzz patterns. */
    generateRegisterFuzz(registers) {
        const commands = [];
        for (const [name, reg] of Object.entries(registers)) {
            if (reg.access === 'r')
                continue; // Skip read-only
            const maxVal = (1 << reg.width) - 1;
            // Boundary values
            const boundaries = [0, 1, maxVal, maxVal - 1, reg.resetValue ?? 0];
            for (const val of boundaries) {
                commands.push({
                    interface: HWInterface.SWD,
                    operation: 'write_register',
                    data: numberToBytes(val, reg.width / 8),
                    address: reg.address,
                    description: `Write 0x${val.toString(16)} to ${name} (addr 0x${reg.address.toString(16)})`,
                });
            }
            // Bit-field specific
            if (reg.fields) {
                for (const field of reg.fields) {
                    const [msb, lsb] = field.bits;
                    const fieldMask = ((1 << (msb - lsb + 1)) - 1) << lsb;
                    commands.push({
                        interface: HWInterface.SWD,
                        operation: 'write_register',
                        data: numberToBytes(fieldMask, reg.width / 8),
                        address: reg.address,
                        description: `Set all bits in field '${field.name}' of ${name}`,
                    });
                }
            }
            // Random values
            for (let i = 0; i < 5; i++) {
                const val = this.prng.nextRange(maxVal + 1);
                commands.push({
                    interface: HWInterface.SWD,
                    operation: 'write_register',
                    data: numberToBytes(val, reg.width / 8),
                    address: reg.address,
                    description: `Random write 0x${val.toString(16)} to ${name}`,
                });
            }
        }
        return commands;
    }
    // ─── Interface-specific fuzzers ─────────────────────────────────────────
    fuzzUART(_target) {
        const ops = ['data', 'break', 'overrun', 'framing_error'];
        const op = this.prng.pick(ops);
        switch (op) {
            case 'break':
                return {
                    interface: HWInterface.UART,
                    operation: 'send_break',
                    data: new Uint8Array(0),
                    description: 'Send UART break condition',
                };
            case 'overrun':
                // Send data faster than target can process
                return {
                    interface: HWInterface.UART,
                    operation: 'burst_send',
                    data: this.prng.randomBytes(4096),
                    description: 'Burst send 4KB to trigger buffer overrun',
                };
            case 'framing_error':
                // Malformed frame (wrong stop bits pattern)
                return {
                    interface: HWInterface.UART,
                    operation: 'send_raw',
                    data: this.generateMalformedUART(),
                    description: 'Send malformed UART frame',
                };
            default: {
                const size = 1 + this.prng.nextRange(256);
                return {
                    interface: HWInterface.UART,
                    operation: 'send',
                    data: this.prng.randomBytes(size),
                    description: `Send ${size} random bytes`,
                };
            }
        }
    }
    fuzzSPI(_target) {
        const ops = ['read', 'write', 'write_read', 'cs_toggle', 'clock_stretch'];
        const op = this.prng.pick(ops);
        const addr = this.prng.nextRange(256);
        const size = 1 + this.prng.nextRange(64);
        return {
            interface: HWInterface.SPI,
            operation: op,
            data: this.prng.randomBytes(size),
            address: addr,
            description: `SPI ${op} addr=0x${addr.toString(16)} len=${size}`,
        };
    }
    fuzzI2C(_target) {
        const ops = ['read', 'write', 'general_call', 'hs_mode', 'repeated_start'];
        const op = this.prng.pick(ops);
        // I2C addresses: 7-bit (0x03-0x77), including reserved ranges
        const addr = this.prng.nextRange(128);
        const size = 1 + this.prng.nextRange(32);
        return {
            interface: HWInterface.I2C,
            operation: op,
            data: this.prng.randomBytes(size),
            address: addr,
            description: `I2C ${op} addr=0x${addr.toString(16)} len=${size}`,
        };
    }
    fuzzUSB() {
        // USB control transfer fuzzing
        const requestTypes = [0x00, 0x01, 0x02, 0x80, 0x81, 0x82, 0xC0, 0xC1];
        const requests = [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 255];
        const bmRequestType = this.prng.pick(requestTypes);
        const bRequest = this.prng.pick(requests);
        const wValue = this.prng.nextRange(65536);
        const wIndex = this.prng.nextRange(65536);
        const wLength = this.prng.nextRange(4096);
        const setup = new Uint8Array(8);
        setup[0] = bmRequestType;
        setup[1] = bRequest;
        setup[2] = wValue & 0xFF;
        setup[3] = (wValue >> 8) & 0xFF;
        setup[4] = wIndex & 0xFF;
        setup[5] = (wIndex >> 8) & 0xFF;
        setup[6] = wLength & 0xFF;
        setup[7] = (wLength >> 8) & 0xFF;
        return {
            interface: HWInterface.USB,
            operation: 'control_transfer',
            data: setup,
            description: `USB control: type=0x${bmRequestType.toString(16)} req=0x${bRequest.toString(16)} val=0x${wValue.toString(16)}`,
        };
    }
    fuzzDebugPort(target) {
        const ops = ['read_mem', 'write_mem', 'read_reg', 'write_reg', 'halt', 'reset'];
        const op = this.prng.pick(ops);
        const base = Number(target.baseAddress ?? 0x20000000n);
        const addr = base + this.prng.nextRange(0x10000);
        const size = this.prng.pick([1, 2, 4]);
        return {
            interface: target.interface,
            operation: op,
            data: this.prng.randomBytes(size),
            address: addr,
            description: `${target.interface.toUpperCase()} ${op} at 0x${addr.toString(16)}`,
        };
    }
    generateMalformedUART() {
        // Create a byte sequence that would cause framing errors
        const buf = new Uint8Array(16);
        this.prng.fillBytes(buf);
        // Insert typical framing error patterns
        buf[0] = 0x00; // false start bit
        buf[buf.length - 1] = 0x00; // missing stop bit
        return buf;
    }
    /** Get all findings. */
    get allFindings() {
        return this.findings;
    }
}
exports.HardwareFuzzer = HardwareFuzzer;
// ─── Helpers ──────────────────────────────────────────────────────────────
function numberToBytes(val, byteLen) {
    const buf = new Uint8Array(byteLen);
    for (let i = 0; i < byteLen; i++) {
        buf[i] = (val >> (i * 8)) & 0xFF;
    }
    return buf;
}
//# sourceMappingURL=fuzzer.js.map