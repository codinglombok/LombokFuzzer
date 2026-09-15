package com.codinglombok.lombokfuzzer;

/**
 * LombokFuzzer — Java port (scaffold).
 * Part of the Lombok Ecosystem. Apache-2.0.
 */
public class LombokFuzzer {
    public static final String VERSION = "0.2.0";

    /** xoshiro256** PRNG. */
    public static class Prng {
        private final long[] s = new long[4];
        public Prng(long seed) {
            long z = seed;
            for (int i = 0; i < 4; i++) {
                z += 0x9e3779b97f4a7c15L;
                z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
                z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
                s[i] = z ^ (z >>> 31);
            }
        }
        private static long rotl(long x, int k) { return (x << k) | (x >>> (64 - k)); }
        public long next() {
            long result = rotl(s[1] * 5, 7) * 9;
            long t = s[1] << 17;
            s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
            s[2] ^= t; s[3] = rotl(s[3], 45);
            return result;
        }
        public int nextRange(int n) { return n <= 0 ? 0 : (int)(Long.remainderUnsigned(next(), n)); }
        public byte[] randomBytes(int n) {
            byte[] buf = new byte[n];
            for (int i = 0; i < n; i++) buf[i] = (byte) next();
            return buf;
        }
    }

    /** FNV-1a 64-bit hash. */
    public static long fnv1a64(byte[] data) {
        long h = 0xcbf29ce484222325L;
        for (byte b : data) { h ^= (b & 0xFF); h *= 0x100000001b3L; }
        return h;
    }

    // TODO: CoverageTracker, MutatorEngine, CorpusStore, CrashAnalyzer, FuzzEngine
}
