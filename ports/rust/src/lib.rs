//! LombokFuzzer — Rust port of the universal fuzzing framework.
//!
//! Part of the Lombok Ecosystem (github.com/codinglombok/LombokFuzzer).
//! Apache-2.0 License.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub const VERSION: &str = "0.2.0";

// ─── PRNG (xoshiro256**) ────────────────────────────────────────────────────

/// Fast PRNG implementing xoshiro256**.
pub struct Prng {
    s: [u64; 4],
}

impl Prng {
    /// Create a new PRNG with the given seed.
    pub fn new(seed: u64) -> Self {
        let mut p = Prng { s: [0; 4] };
        let mut z = seed;
        for i in 0..4 {
            z = z.wrapping_add(0x9e3779b97f4a7c15);
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            p.s[i] = z ^ (z >> 31);
        }
        p
    }

    fn rotl(x: u64, k: u32) -> u64 {
        (x << k) | (x >> (64 - k))
    }

    /// Return the next pseudo-random u64.
    pub fn next_u64(&mut self) -> u64 {
        let result = Self::rotl(self.s[1].wrapping_mul(5), 7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = Self::rotl(self.s[3], 45);
        result
    }

    /// Return a random number in [0, n).
    pub fn next_range(&mut self, n: usize) -> usize {
        if n == 0 { return 0; }
        (self.next_u64() % n as u64) as usize
    }

    /// Return n random bytes.
    pub fn random_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
}

// ─── Hash (FNV-1a 64-bit) ──────────────────────────────────────────────────

/// Compute the FNV-1a 64-bit hash of data.
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ─── Coverage Tracker ───────────────────────────────────────────────────────

/// Edge coverage tracker using a fixed-size bitmap.
pub struct CoverageTracker {
    bitmap: Vec<u8>,
    edges_found: usize,
}

impl CoverageTracker {
    pub fn new(size: usize) -> Self {
        let size = if size == 0 { 65536 } else { size };
        CoverageTracker {
            bitmap: vec![0u8; size],
            edges_found: 0,
        }
    }

    /// Record an edge hit. Returns true if the edge is new.
    pub fn record_edge(&mut self, from: u64, to: u64) -> bool {
        let idx = ((from ^ to) % self.bitmap.len() as u64) as usize;
        if self.bitmap[idx] == 0 {
            self.bitmap[idx] = 1;
            self.edges_found += 1;
            true
        } else {
            self.bitmap[idx] = self.bitmap[idx].saturating_add(1);
            false
        }
    }

    pub fn edges_found(&self) -> usize { self.edges_found }

    pub fn coverage_percent(&self) -> f64 {
        self.edges_found as f64 / self.bitmap.len() as f64 * 100.0
    }

    pub fn reset(&mut self) {
        self.bitmap.fill(0);
        self.edges_found = 0;
    }
}

// ─── Mutator Engine ─────────────────────────────────────────────────────────

/// Mutation strategies.
#[derive(Clone, Copy, Debug)]
pub enum MutatorStrategy {
    BitFlip,
    ByteFlip,
    Arithmetic,
    Interesting,
    Havoc,
}

/// Applies mutations to input bytes.
pub struct MutatorEngine {
    strategies: Vec<MutatorStrategy>,
}

impl MutatorEngine {
    pub fn new() -> Self {
        MutatorEngine {
            strategies: vec![
                MutatorStrategy::BitFlip,
                MutatorStrategy::ByteFlip,
                MutatorStrategy::Arithmetic,
                MutatorStrategy::Interesting,
                MutatorStrategy::Havoc,
            ],
        }
    }

    /// Apply a random mutation to the input.
    pub fn mutate(&self, data: &[u8], prng: &mut Prng) -> Vec<u8> {
        if data.is_empty() {
            return prng.random_bytes(prng.next_range(64) + 1);
        }

        let mut out = data.to_vec();
        let strategy = self.strategies[prng.next_range(self.strategies.len())];

        match strategy {
            MutatorStrategy::BitFlip => {
                let pos = prng.next_range(out.len());
                let bit = prng.next_range(8);
                out[pos] ^= 1 << bit;
            }
            MutatorStrategy::ByteFlip => {
                let pos = prng.next_range(out.len());
                out[pos] ^= 0xFF;
            }
            MutatorStrategy::Arithmetic => {
                let pos = prng.next_range(out.len());
                let delta = (prng.next_range(70) as i8) - 35;
                out[pos] = out[pos].wrapping_add(delta as u8);
            }
            MutatorStrategy::Interesting => {
                let interesting: &[u8] = &[0, 1, 0x7F, 0x80, 0xFF];
                let pos = prng.next_range(out.len());
                out[pos] = interesting[prng.next_range(interesting.len())];
            }
            MutatorStrategy::Havoc => {
                let rounds = prng.next_range(8) + 1;
                for _ in 0..rounds {
                    let pos = prng.next_range(out.len());
                    out[pos] = prng.next_u64() as u8;
                }
            }
        }

        out
    }
}

impl Default for MutatorEngine {
    fn default() -> Self { Self::new() }
}

// ─── Corpus Store ───────────────────────────────────────────────────────────

/// A single fuzz input.
#[derive(Clone)]
pub struct FuzzInput {
    pub data: Vec<u8>,
    pub hash: u64,
    pub depth: u32,
    pub energy: f64,
}

/// Manages the input corpus.
pub struct CorpusStore {
    entries: Vec<FuzzInput>,
    hashes: HashSet<u64>,
}

impl CorpusStore {
    pub fn new() -> Self {
        CorpusStore { entries: Vec::new(), hashes: HashSet::new() }
    }

    pub fn add(&mut self, input: FuzzInput) -> bool {
        if self.hashes.contains(&input.hash) { return false; }
        self.hashes.insert(input.hash);
        self.entries.push(input);
        true
    }

    pub fn pick(&self, prng: &mut Prng) -> Option<&FuzzInput> {
        if self.entries.is_empty() { return None; }
        Some(&self.entries[prng.next_range(self.entries.len())])
    }

    pub fn size(&self) -> usize { self.entries.len() }
}

impl Default for CorpusStore {
    fn default() -> Self { Self::new() }
}

// ─── Crash Analyzer ─────────────────────────────────────────────────────────

/// Crash information.
pub struct CrashInfo {
    pub id: String,
    pub input: FuzzInput,
    pub error: String,
    pub is_duplicate: bool,
}

/// Detects and deduplicates crashes.
pub struct CrashAnalyzer {
    crashes: Vec<CrashInfo>,
    hashes: HashSet<u64>,
}

impl CrashAnalyzer {
    pub fn new() -> Self {
        CrashAnalyzer { crashes: Vec::new(), hashes: HashSet::new() }
    }

    pub fn record(&mut self, input: &FuzzInput, error: &str) -> bool {
        let h = fnv1a64(error.as_bytes());
        let is_dup = self.hashes.contains(&h);
        self.hashes.insert(h);
        self.crashes.push(CrashInfo {
            id: format!("crash-{:016x}", h),
            input: input.clone(),
            error: error.to_string(),
            is_duplicate: is_dup,
        });
        !is_dup
    }

    pub fn unique_count(&self) -> usize { self.hashes.len() }
}

impl Default for CrashAnalyzer {
    fn default() -> Self { Self::new() }
}

// ─── Fuzz Engine ────────────────────────────────────────────────────────────

/// Campaign statistics.
pub struct FuzzStats {
    pub total_executions: u64,
    pub corpus_size: usize,
    pub unique_crashes: usize,
    pub edges_found: usize,
    pub coverage_percent: f64,
    pub elapsed_ms: u64,
}

/// Configuration for a fuzzing campaign.
pub struct FuzzConfig {
    pub name: String,
    pub seed: u64,
    pub max_executions: u64,
    pub max_time_secs: u64,
    pub max_input_size: usize,
    pub target: Box<dyn Fn(&[u8]) -> Result<(), String>>,
}

/// The main fuzzing engine.
pub struct FuzzEngine {
    config: FuzzConfig,
    prng: Prng,
    mutator: MutatorEngine,
    corpus: CorpusStore,
    coverage: CoverageTracker,
    crashes: CrashAnalyzer,
}

impl FuzzEngine {
    pub fn new(config: FuzzConfig) -> Self {
        let prng = Prng::new(config.seed);
        FuzzEngine {
            config,
            prng,
            mutator: MutatorEngine::new(),
            corpus: CorpusStore::new(),
            coverage: CoverageTracker::new(65536),
            crashes: CrashAnalyzer::new(),
        }
    }

    /// Run the fuzzing campaign. Blocks until done.
    pub fn run(&mut self) -> FuzzStats {
        let start = Instant::now();

        // Seed corpus
        if self.corpus.size() == 0 {
            let seed = self.prng.random_bytes(self.prng.next_range(64) + 1);
            let hash = fnv1a64(&seed);
            self.corpus.add(FuzzInput { data: seed, hash, depth: 0, energy: 1.0 });
        }

        let mut exec_count: u64 = 0;

        loop {
            if self.config.max_executions > 0 && exec_count >= self.config.max_executions {
                break;
            }
            if self.config.max_time_secs > 0
                && start.elapsed() > Duration::from_secs(self.config.max_time_secs) {
                break;
            }

            let parent = match self.corpus.pick(&mut self.prng) {
                Some(p) => p.clone(),
                None => break,
            };

            let mutated = self.mutator.mutate(&parent.data, &mut self.prng);
            let hash = fnv1a64(&mutated);
            let input = FuzzInput {
                data: mutated.clone(),
                hash,
                depth: parent.depth + 1,
                energy: parent.energy,
            };

            // Execute
            let result = (self.config.target)(&mutated);
            exec_count += 1;

            // Coverage
            let edge_hash = fnv1a64(&mutated[..mutated.len().min(8)]);
            if self.coverage.record_edge(parent.hash, edge_hash) {
                self.corpus.add(input.clone());
            }

            // Crash
            if let Err(err) = result {
                self.crashes.record(&input, &err);
            }
        }

        FuzzStats {
            total_executions: exec_count,
            corpus_size: self.corpus.size(),
            unique_crashes: self.crashes.unique_count(),
            edges_found: self.coverage.edges_found(),
            coverage_percent: self.coverage.coverage_percent(),
            elapsed_ms: start.elapsed().as_millis() as u64,
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prng_deterministic() {
        let mut a = Prng::new(42);
        let mut b = Prng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn test_prng_range() {
        let mut p = Prng::new(42);
        for _ in 0..1000 {
            let v = p.next_range(10);
            assert!(v < 10);
        }
    }

    #[test]
    fn test_fnv1a64() {
        let h1 = fnv1a64(b"hello");
        let h2 = fnv1a64(b"world");
        let h3 = fnv1a64(b"hello");
        assert_ne!(h1, h2);
        assert_eq!(h1, h3);
    }

    #[test]
    fn test_coverage_tracker() {
        let mut ct = CoverageTracker::new(1024);
        assert_eq!(ct.edges_found(), 0);
        assert!(ct.record_edge(1, 2));
        assert_eq!(ct.edges_found(), 1);
        assert!(!ct.record_edge(1, 2));
        ct.reset();
        assert_eq!(ct.edges_found(), 0);
    }

    #[test]
    fn test_mutator() {
        let mut prng = Prng::new(42);
        let me = MutatorEngine::new();
        let data = b"hello world";
        let mutated = me.mutate(data, &mut prng);
        assert!(!mutated.is_empty());
        let empty = me.mutate(&[], &mut prng);
        assert!(!empty.is_empty());
    }

    #[test]
    fn test_corpus_store() {
        let mut cs = CorpusStore::new();
        assert_eq!(cs.size(), 0);
        let input = FuzzInput { data: vec![1, 2, 3], hash: 123, depth: 0, energy: 1.0 };
        assert!(cs.add(input.clone()));
        assert_eq!(cs.size(), 1);
        assert!(!cs.add(input));
    }

    #[test]
    fn test_crash_analyzer() {
        let mut ca = CrashAnalyzer::new();
        let input = FuzzInput { data: vec![0xFF], hash: 1, depth: 0, energy: 1.0 };
        assert!(ca.record(&input, "segfault"));
        assert_eq!(ca.unique_count(), 1);
        assert!(!ca.record(&input, "segfault"));
        assert!(ca.record(&input, "different"));
        assert_eq!(ca.unique_count(), 2);
    }

    #[test]
    fn test_fuzz_engine() {
        let mut engine = FuzzEngine::new(FuzzConfig {
            name: "test".to_string(),
            seed: 42,
            max_executions: 500,
            max_time_secs: 0,
            max_input_size: 4096,
            target: Box::new(|data| {
                if data.len() > 3 && data[0] == 0xFF && data[1] == 0xFE {
                    return Err("crash".to_string());
                }
                Ok(())
            }),
        });

        let stats = engine.run();
        assert_eq!(stats.total_executions, 500);
        assert!(stats.corpus_size > 0);
    }
}
