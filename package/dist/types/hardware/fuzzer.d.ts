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
import type { PRNG } from '../utils/prng.js';
export declare enum HWInterface {
    JTAG = "jtag",
    SWD = "swd",
    UART = "uart",
    SPI = "spi",
    I2C = "i2c",
    USB = "usb"
}
export interface HWFuzzTarget {
    interface: HWInterface;
    deviceId?: string;
    baseAddress?: bigint;
    registers?: RegisterMap;
    baudRate?: number;
    clockSpeed?: number;
}
export interface RegisterMap {
    [name: string]: RegisterDef;
}
export interface RegisterDef {
    address: number;
    width: 8 | 16 | 32;
    access: 'r' | 'w' | 'rw';
    fields?: BitField[];
    resetValue?: number;
}
export interface BitField {
    name: string;
    bits: [number, number];
    values?: Record<string, number>;
}
export interface HWFuzzCommand {
    interface: HWInterface;
    operation: string;
    data: Uint8Array;
    address?: number;
    description: string;
}
export interface HWFinding {
    type: string;
    description: string;
    command: HWFuzzCommand;
    response?: Uint8Array;
    severity: 'critical' | 'high' | 'medium' | 'low';
}
export declare class HardwareFuzzer {
    private readonly prng;
    private readonly findings;
    constructor(prng: PRNG);
    /** Generate fuzz commands for a hardware target. */
    generateCommands(target: HWFuzzTarget, count?: number): HWFuzzCommand[];
    /** Generate register fuzz patterns. */
    generateRegisterFuzz(registers: RegisterMap): HWFuzzCommand[];
    private fuzzUART;
    private fuzzSPI;
    private fuzzI2C;
    private fuzzUSB;
    private fuzzDebugPort;
    private generateMalformedUART;
    /** Get all findings. */
    get allFindings(): readonly HWFinding[];
}
//# sourceMappingURL=fuzzer.d.ts.map