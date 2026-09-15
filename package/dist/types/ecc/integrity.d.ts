/**
 * LombokFuzzer — ECC Integrity Layer
 *
 * Integrates LombokECC (Reed–Solomon RS(255,239)) to protect corpus
 * entries and crash reproducers against silent corruption on disk.
 *
 * Each protected blob is stored as:
 *   [4-byte magic] [4-byte original-length] [RS-encoded blocks…]
 *
 * On read, the RS decoder corrects up to 8 symbol errors per 255-byte
 * block. If corruption exceeds that, the entry is flagged rather than
 * silently returning bad data.
 *
 * LombokECC is an optional peer dependency. If not installed, the
 * integrity layer operates in pass-through mode (no protection).
 *
 * @license Apache-2.0
 */
/** Status of an integrity check. */
export declare enum IntegrityStatus {
    /** No ECC protection (pass-through). */
    Unprotected = "unprotected",
    /** Valid — no errors. */
    Valid = "valid",
    /** Corrected — had errors but RS fixed them. */
    Corrected = "corrected",
    /** Corrupted — errors exceed RS correction capacity. */
    Corrupted = "corrupted"
}
/** Result of encoding or decoding a blob. */
export interface IntegrityResult {
    /** The data (original on encode, restored on decode). */
    data: Uint8Array;
    /** Status. */
    status: IntegrityStatus;
    /** Number of RS blocks processed. */
    blocks: number;
    /** Number of symbol errors corrected (decode only). */
    errorsCorrected: number;
    /** Number of blocks that could not be corrected (decode only). */
    uncorrectableBlocks: number;
}
/** Configuration for the ECC integrity layer. */
export interface EccConfig {
    /** Enable ECC protection. */
    enabled: boolean;
    /** RS data symbols per block (default 239 for RS(255,239)). */
    dataSymbols: number;
    /** RS total symbols per block (default 255). */
    totalSymbols: number;
}
export declare class EccIntegrity {
    private readonly config;
    private eccAvailable;
    private eccModule;
    constructor(config?: Partial<EccConfig>);
    /**
     * Attempt to load LombokECC. Must be called before encode/decode.
     * Returns true if LombokECC is available.
     */
    init(): Promise<boolean>;
    /** Whether ECC protection is active. */
    get isActive(): boolean;
    /**
     * Encode data with Reed–Solomon protection.
     * Returns the protected blob (larger than input due to parity bytes).
     */
    encode(data: Uint8Array): IntegrityResult;
    /**
     * Decode an ECC-protected blob and verify / correct errors.
     * Returns the original data with integrity status.
     */
    decode(blob: Uint8Array): IntegrityResult;
    /**
     * Verify a blob without decoding (quick integrity check).
     */
    verify(blob: Uint8Array): IntegrityStatus;
    /** Check if a blob starts with the ECC magic header. */
    isEccBlob(blob: Uint8Array): boolean;
    private rsEncode;
    private rsDecode;
}
//# sourceMappingURL=integrity.d.ts.map