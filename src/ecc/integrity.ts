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

// ─── Types ──────────────────────────────────────────────────────────────────

/** Status of an integrity check. */
export enum IntegrityStatus {
  /** No ECC protection (pass-through). */
  Unprotected = 'unprotected',
  /** Valid — no errors. */
  Valid = 'valid',
  /** Corrected — had errors but RS fixed them. */
  Corrected = 'corrected',
  /** Corrupted — errors exceed RS correction capacity. */
  Corrupted = 'corrupted',
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

// ─── Constants ──────────────────────────────────────────────────────────────

/** Magic bytes identifying an ECC-protected blob. */
const ECC_MAGIC = new Uint8Array([0x4C, 0x4B, 0x45, 0x43]); // "LKEC"

/** Default RS(255,239) parameters. */
const DEFAULT_DATA_SYMBOLS = 239;
const DEFAULT_TOTAL_SYMBOLS = 255;

// ─── ECC Integrity Manager ─────────────────────────────────────────────────

export class EccIntegrity {
  private readonly config: EccConfig;
  private eccAvailable = false;
  private eccModule: any = null;

  constructor(config?: Partial<EccConfig>) {
    this.config = {
      enabled: config?.enabled ?? true,
      dataSymbols: config?.dataSymbols ?? DEFAULT_DATA_SYMBOLS,
      totalSymbols: config?.totalSymbols ?? DEFAULT_TOTAL_SYMBOLS,
    };
  }

  /**
   * Attempt to load LombokECC. Must be called before encode/decode.
   * Returns true if LombokECC is available.
   */
  async init(): Promise<boolean> {
    if (!this.config.enabled) return false;

    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      this.eccModule = await import(/* webpackIgnore: true */ 'lombokecc' as string);
      this.eccAvailable = true;
      return true;
    } catch {
      this.eccAvailable = false;
      return false;
    }
  }

  /** Whether ECC protection is active. */
  get isActive(): boolean {
    return this.config.enabled && this.eccAvailable;
  }

  /**
   * Encode data with Reed–Solomon protection.
   * Returns the protected blob (larger than input due to parity bytes).
   */
  encode(data: Uint8Array): IntegrityResult {
    if (!this.isActive) {
      return {
        data,
        status: IntegrityStatus.Unprotected,
        blocks: 0,
        errorsCorrected: 0,
        uncorrectableBlocks: 0,
      };
    }

    const dataSymbols = this.config.dataSymbols;
    const totalSymbols = this.config.totalSymbols;
    const blockCount = Math.ceil(data.length / dataSymbols);

    // Header: magic (4) + original length (4)
    const headerSize = 8;
    const encodedSize = headerSize + blockCount * totalSymbols;
    const encoded = new Uint8Array(encodedSize);

    // Write header
    encoded.set(ECC_MAGIC, 0);
    new DataView(encoded.buffer).setUint32(4, data.length, false);

    // Encode each block
    let offset = headerSize;
    for (let i = 0; i < blockCount; i++) {
      const start = i * dataSymbols;
      const end = Math.min(start + dataSymbols, data.length);
      const block = new Uint8Array(dataSymbols);
      block.set(data.subarray(start, end));

      // Pad short last block with zeros (implicit)
      const codeword = this.rsEncode(block);
      encoded.set(codeword, offset);
      offset += totalSymbols;
    }

    return {
      data: encoded,
      status: IntegrityStatus.Valid,
      blocks: blockCount,
      errorsCorrected: 0,
      uncorrectableBlocks: 0,
    };
  }

  /**
   * Decode an ECC-protected blob and verify / correct errors.
   * Returns the original data with integrity status.
   */
  decode(blob: Uint8Array): IntegrityResult {
    // Check if this is an ECC blob
    if (!this.isEccBlob(blob)) {
      return {
        data: blob,
        status: IntegrityStatus.Unprotected,
        blocks: 0,
        errorsCorrected: 0,
        uncorrectableBlocks: 0,
      };
    }

    const totalSymbols = this.config.totalSymbols;
    const dataSymbols = this.config.dataSymbols;

    // Read header
    const originalLength = new DataView(blob.buffer, blob.byteOffset).getUint32(4, false);
    const headerSize = 8;
    const blockCount = Math.ceil(originalLength / dataSymbols);

    let totalErrors = 0;
    let uncorrectable = 0;
    const output = new Uint8Array(originalLength);

    // Decode each block
    for (let i = 0; i < blockCount; i++) {
      const blockStart = headerSize + i * totalSymbols;
      const codeword = blob.subarray(blockStart, blockStart + totalSymbols);

      const { data: decoded, errors, ok } = this.rsDecode(codeword);

      if (!ok) {
        uncorrectable++;
      }
      totalErrors += errors;

      // Copy decoded data symbols to output
      const outStart = i * dataSymbols;
      const outEnd = Math.min(outStart + dataSymbols, originalLength);
      output.set(decoded.subarray(0, outEnd - outStart), outStart);
    }

    let status: IntegrityStatus;
    if (uncorrectable > 0) {
      status = IntegrityStatus.Corrupted;
    } else if (totalErrors > 0) {
      status = IntegrityStatus.Corrected;
    } else {
      status = IntegrityStatus.Valid;
    }

    return {
      data: output,
      status,
      blocks: blockCount,
      errorsCorrected: totalErrors,
      uncorrectableBlocks: uncorrectable,
    };
  }

  /**
   * Verify a blob without decoding (quick integrity check).
   */
  verify(blob: Uint8Array): IntegrityStatus {
    if (!this.isEccBlob(blob)) return IntegrityStatus.Unprotected;
    return this.decode(blob).status;
  }

  /** Check if a blob starts with the ECC magic header. */
  isEccBlob(blob: Uint8Array): boolean {
    if (blob.length < 8) return false;
    return blob[0] === ECC_MAGIC[0]
      && blob[1] === ECC_MAGIC[1]
      && blob[2] === ECC_MAGIC[2]
      && blob[3] === ECC_MAGIC[3];
  }

  // ─── RS operations (delegate to LombokECC or fallback) ────────────────

  private rsEncode(data: Uint8Array): Uint8Array {
    if (this.eccModule?.encode) {
      return this.eccModule.encode(data);
    }
    // Fallback: no-parity identity (data is unprotected but format-valid)
    const totalSymbols = this.config.totalSymbols;
    const codeword = new Uint8Array(totalSymbols);
    codeword.set(data);
    return codeword;
  }

  private rsDecode(codeword: Uint8Array): { data: Uint8Array; errors: number; ok: boolean } {
    if (this.eccModule?.decode) {
      try {
        const result = this.eccModule.decode(codeword);
        return {
          data: result.data ?? codeword.subarray(0, this.config.dataSymbols),
          errors: result.errorsFixed ?? 0,
          ok: result.ok !== false,
        };
      } catch {
        return {
          data: codeword.subarray(0, this.config.dataSymbols),
          errors: 0,
          ok: false,
        };
      }
    }
    // Fallback: no correction, just strip parity
    return {
      data: codeword.subarray(0, this.config.dataSymbols),
      errors: 0,
      ok: true,
    };
  }
}
