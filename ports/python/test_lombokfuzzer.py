"""Tests for LombokFuzzer Python port."""

import unittest
from lombokfuzzer import (
    PRNG, fnv1a64, CoverageTracker, MutatorEngine,
    CorpusStore, FuzzInput, CrashAnalyzer, FuzzEngine, FuzzConfig, FuzzStats,
)


class TestPRNG(unittest.TestCase):
    def test_deterministic(self):
        a = PRNG(42)
        b = PRNG(42)
        for _ in range(100):
            self.assertEqual(a.next(), b.next())

    def test_different_seeds(self):
        a = PRNG(1)
        b = PRNG(2)
        self.assertNotEqual(a.next(), b.next())

    def test_range(self):
        p = PRNG(42)
        for _ in range(1000):
            v = p.next_range(10)
            self.assertGreaterEqual(v, 0)
            self.assertLess(v, 10)

    def test_random_bytes(self):
        p = PRNG(42)
        data = p.random_bytes(16)
        self.assertEqual(len(data), 16)
        self.assertIsInstance(data, bytes)


class TestHash(unittest.TestCase):
    def test_consistency(self):
        self.assertEqual(fnv1a64(b"hello"), fnv1a64(b"hello"))

    def test_different_inputs(self):
        self.assertNotEqual(fnv1a64(b"hello"), fnv1a64(b"world"))


class TestCoverageTracker(unittest.TestCase):
    def test_new_edge(self):
        ct = CoverageTracker(1024)
        self.assertEqual(ct.edges_found, 0)
        self.assertTrue(ct.record_edge(1, 2))
        self.assertEqual(ct.edges_found, 1)

    def test_duplicate_edge(self):
        ct = CoverageTracker(1024)
        ct.record_edge(1, 2)
        self.assertFalse(ct.record_edge(1, 2))

    def test_reset(self):
        ct = CoverageTracker(1024)
        ct.record_edge(1, 2)
        ct.reset()
        self.assertEqual(ct.edges_found, 0)

    def test_coverage_percent(self):
        ct = CoverageTracker(100)
        ct.record_edge(1, 2)
        self.assertAlmostEqual(ct.coverage_percent, 1.0)


class TestMutatorEngine(unittest.TestCase):
    def test_mutate(self):
        prng = PRNG(42)
        me = MutatorEngine(prng)
        data = b"hello world test"
        mutated = me.mutate(data)
        self.assertIsInstance(mutated, bytes)
        self.assertEqual(len(mutated), len(data))

    def test_empty_input(self):
        prng = PRNG(42)
        me = MutatorEngine(prng)
        result = me.mutate(b"")
        self.assertGreater(len(result), 0)


class TestCorpusStore(unittest.TestCase):
    def test_add(self):
        cs = CorpusStore()
        self.assertEqual(cs.size, 0)
        inp = FuzzInput(data=b"test", hash=fnv1a64(b"test"))
        self.assertTrue(cs.add(inp))
        self.assertEqual(cs.size, 1)

    def test_duplicate(self):
        cs = CorpusStore()
        inp = FuzzInput(data=b"test", hash=fnv1a64(b"test"))
        cs.add(inp)
        self.assertFalse(cs.add(inp))

    def test_pick(self):
        cs = CorpusStore()
        cs.add(FuzzInput(data=b"a", hash=1))
        prng = PRNG(42)
        picked = cs.pick(prng)
        self.assertIsNotNone(picked)


class TestCrashAnalyzer(unittest.TestCase):
    def test_unique_crash(self):
        ca = CrashAnalyzer()
        inp = FuzzInput(data=b"x", hash=1)
        self.assertTrue(ca.record(inp, "segfault"))
        self.assertEqual(ca.unique_count, 1)

    def test_duplicate_crash(self):
        ca = CrashAnalyzer()
        inp = FuzzInput(data=b"x", hash=1)
        ca.record(inp, "segfault")
        self.assertFalse(ca.record(inp, "segfault"))

    def test_different_errors(self):
        ca = CrashAnalyzer()
        inp = FuzzInput(data=b"x", hash=1)
        ca.record(inp, "segfault")
        self.assertTrue(ca.record(inp, "overflow"))
        self.assertEqual(ca.unique_count, 2)


class TestFuzzEngine(unittest.TestCase):
    def test_basic_run(self):
        def target(data):
            if len(data) > 3 and data[0] == 0xFF and data[1] == 0xFE:
                raise ValueError("crash")

        engine = FuzzEngine(FuzzConfig(
            name="test",
            seed=42,
            max_executions=500,
            target=target,
        ))
        stats = engine.run()
        self.assertEqual(stats.total_executions, 500)
        self.assertGreater(stats.corpus_size, 0)

    def test_no_target(self):
        engine = FuzzEngine(FuzzConfig(seed=42, max_executions=10))
        stats = engine.run()
        self.assertEqual(stats.total_executions, 10)

    def test_stop(self):
        engine = FuzzEngine(FuzzConfig(seed=42, max_executions=0, max_time_seconds=1))
        import threading
        threading.Timer(0.1, engine.stop).start()
        stats = engine.run()
        self.assertGreater(stats.total_executions, 0)


if __name__ == "__main__":
    unittest.main()
