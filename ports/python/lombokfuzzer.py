"""
LombokFuzzer — Python port of the universal fuzzing framework.

Part of the Lombok Ecosystem (github.com/codinglombok/LombokFuzzer).
Apache-2.0 License.
"""

from __future__ import annotations
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

__version__ = "0.2.0"

# ─── PRNG (xoshiro256**) ────────────────────────────────────────────────────

class PRNG:
    """Fast PRNG implementing xoshiro256**."""

    MASK = (1 << 64) - 1

    def __init__(self, seed: int) -> None:
        self.s = [0, 0, 0, 0]
        z = seed & self.MASK
        for i in range(4):
            z = (z + 0x9E3779B97F4A7C15) & self.MASK
            z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & self.MASK
            z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & self.MASK
            self.s[i] = (z ^ (z >> 31)) & self.MASK

    @staticmethod
    def _rotl(x: int, k: int) -> int:
        mask = (1 << 64) - 1
        return ((x << k) | (x >> (64 - k))) & mask

    def next(self) -> int:
        s = self.s
        result = (self._rotl((s[1] * 5) & self.MASK, 7) * 9) & self.MASK
        t = (s[1] << 17) & self.MASK
        s[2] ^= s[0]
        s[3] ^= s[1]
        s[1] ^= s[2]
        s[0] ^= s[3]
        s[2] ^= t
        s[3] = self._rotl(s[3], 45)
        for i in range(4):
            s[i] &= self.MASK
        return result

    def next_range(self, n: int) -> int:
        if n <= 0:
            return 0
        return self.next() % n

    def random_bytes(self, n: int) -> bytes:
        return bytes(self.next() & 0xFF for _ in range(n))

    def pick(self, items: list):
        if not items:
            return None
        return items[self.next_range(len(items))]


# ─── Hash (FNV-1a 64-bit) ───────────────────────────────────────────────────

def fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    mask = (1 << 64) - 1
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & mask
    return h


# ─── Coverage Tracker ────────────────────────────────────────────────────────

class CoverageTracker:
    """Edge coverage tracker using a fixed-size bitmap."""

    def __init__(self, size: int = 65536) -> None:
        self._bitmap = bytearray(size)
        self._edges_found = 0

    def record_edge(self, from_: int, to: int) -> bool:
        idx = (from_ ^ to) % len(self._bitmap)
        if self._bitmap[idx] == 0:
            self._bitmap[idx] = 1
            self._edges_found += 1
            return True
        self._bitmap[idx] = min(self._bitmap[idx] + 1, 255)
        return False

    @property
    def edges_found(self) -> int:
        return self._edges_found

    @property
    def coverage_percent(self) -> float:
        return self._edges_found / len(self._bitmap) * 100

    def reset(self) -> None:
        for i in range(len(self._bitmap)):
            self._bitmap[i] = 0
        self._edges_found = 0


# ─── Mutator Engine ──────────────────────────────────────────────────────────

class MutatorStrategy:
    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    ARITHMETIC = "arithmetic"
    INTERESTING = "interesting"
    HAVOC = "havoc"


class MutatorEngine:
    """Applies mutations to input bytes."""

    STRATEGIES = [
        MutatorStrategy.BIT_FLIP,
        MutatorStrategy.BYTE_FLIP,
        MutatorStrategy.ARITHMETIC,
        MutatorStrategy.INTERESTING,
        MutatorStrategy.HAVOC,
    ]

    INTERESTING_BYTES = [0, 1, 0x7F, 0x80, 0xFF]

    def __init__(self, prng: PRNG) -> None:
        self.prng = prng

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return self.prng.random_bytes(self.prng.next_range(64) + 1)

        buf = bytearray(data)
        strategy = self.prng.pick(self.STRATEGIES)

        if strategy == MutatorStrategy.BIT_FLIP:
            pos = self.prng.next_range(len(buf))
            bit = self.prng.next_range(8)
            buf[pos] ^= 1 << bit

        elif strategy == MutatorStrategy.BYTE_FLIP:
            pos = self.prng.next_range(len(buf))
            buf[pos] ^= 0xFF

        elif strategy == MutatorStrategy.ARITHMETIC:
            pos = self.prng.next_range(len(buf))
            delta = self.prng.next_range(70) - 35
            buf[pos] = (buf[pos] + delta) & 0xFF

        elif strategy == MutatorStrategy.INTERESTING:
            pos = self.prng.next_range(len(buf))
            buf[pos] = self.prng.pick(self.INTERESTING_BYTES)

        elif strategy == MutatorStrategy.HAVOC:
            rounds = self.prng.next_range(8) + 1
            for _ in range(rounds):
                pos = self.prng.next_range(len(buf))
                buf[pos] = self.prng.next() & 0xFF

        return bytes(buf)


# ─── Corpus Store ────────────────────────────────────────────────────────────

@dataclass
class FuzzInput:
    data: bytes
    hash: int
    depth: int = 0
    energy: float = 1.0
    executions: int = 0
    created_at: float = field(default_factory=time.time)


class CorpusStore:
    """Manages the input corpus."""

    def __init__(self) -> None:
        self._entries: list[FuzzInput] = []
        self._hashes: set[int] = set()

    def add(self, inp: FuzzInput) -> bool:
        if inp.hash in self._hashes:
            return False
        self._hashes.add(inp.hash)
        self._entries.append(inp)
        return True

    def pick(self, prng: PRNG) -> Optional[FuzzInput]:
        return prng.pick(self._entries)

    @property
    def size(self) -> int:
        return len(self._entries)


# ─── Crash Analyzer ──────────────────────────────────────────────────────────

@dataclass
class CrashInfo:
    id: str
    input: FuzzInput
    error: str
    is_duplicate: bool
    discovered_at: float = field(default_factory=time.time)


class CrashAnalyzer:
    """Detects and deduplicates crashes."""

    def __init__(self) -> None:
        self._crashes: list[CrashInfo] = []
        self._hashes: set[int] = set()

    def record(self, inp: FuzzInput, error: str) -> bool:
        h = fnv1a64(error.encode())
        is_dup = h in self._hashes
        self._hashes.add(h)
        self._crashes.append(CrashInfo(
            id=f"crash-{h:016x}",
            input=inp,
            error=error,
            is_duplicate=is_dup,
        ))
        return not is_dup

    @property
    def unique_count(self) -> int:
        return len(self._hashes)


# ─── Fuzz Engine ─────────────────────────────────────────────────────────────

@dataclass
class FuzzStats:
    total_executions: int = 0
    corpus_size: int = 0
    unique_crashes: int = 0
    edges_found: int = 0
    coverage_percent: float = 0.0
    elapsed_ms: int = 0


@dataclass
class FuzzConfig:
    name: str = "unnamed"
    seed: int = 42
    max_executions: int = 0
    max_time_seconds: int = 0
    max_input_size: int = 4096
    target: Optional[Callable[[bytes], None]] = None


class FuzzEngine:
    """The main fuzzing engine."""

    def __init__(self, config: FuzzConfig) -> None:
        self.config = config
        self.prng = PRNG(config.seed)
        self.mutator = MutatorEngine(self.prng)
        self.corpus = CorpusStore()
        self.coverage = CoverageTracker(65536)
        self.crashes = CrashAnalyzer()
        self._stop = False

    def run(self) -> FuzzStats:
        start = time.monotonic()
        self._stop = False

        # Seed corpus
        if self.corpus.size == 0:
            seed_data = self.prng.random_bytes(self.prng.next_range(64) + 1)
            self.corpus.add(FuzzInput(data=seed_data, hash=fnv1a64(seed_data)))

        exec_count = 0

        while not self._stop:
            if self.config.max_executions > 0 and exec_count >= self.config.max_executions:
                break
            if self.config.max_time_seconds > 0:
                elapsed = time.monotonic() - start
                if elapsed > self.config.max_time_seconds:
                    break

            parent = self.corpus.pick(self.prng)
            if parent is None:
                break

            mutated = self.mutator.mutate(parent.data)
            h = fnv1a64(mutated)
            inp = FuzzInput(data=mutated, hash=h, depth=parent.depth + 1, energy=parent.energy)

            # Execute
            crashed = False
            error_msg = None
            if self.config.target:
                try:
                    self.config.target(mutated)
                except Exception as e:
                    crashed = True
                    error_msg = str(e)

            exec_count += 1

            # Coverage
            edge_hash = fnv1a64(mutated[:min(len(mutated), 8)])
            if self.coverage.record_edge(parent.hash, edge_hash):
                self.corpus.add(inp)

            # Crash
            if crashed and error_msg:
                self.crashes.record(inp, error_msg)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return FuzzStats(
            total_executions=exec_count,
            corpus_size=self.corpus.size,
            unique_crashes=self.crashes.unique_count,
            edges_found=self.coverage.edges_found,
            coverage_percent=self.coverage.coverage_percent,
            elapsed_ms=elapsed_ms,
        )

    def stop(self) -> None:
        self._stop = True
