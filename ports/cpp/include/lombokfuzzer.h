// LombokFuzzer — C++ port (scaffold)
// Part of the Lombok Ecosystem. Apache-2.0.
#pragma once
#include <cstdint>
#include <vector>
#include <string>
namespace lombokfuzzer {
  constexpr const char* VERSION = "0.2.0";
  class Prng {
    uint64_t s[4];
    static uint64_t rotl(uint64_t x, int k);
  public:
    explicit Prng(uint64_t seed);
    uint64_t next();
    int next_range(int n);
    std::vector<uint8_t> random_bytes(int n);
  };
  uint64_t fnv1a64(const uint8_t* data, size_t len);
  // TODO: CoverageTracker, MutatorEngine, CorpusStore, CrashAnalyzer, FuzzEngine
}
