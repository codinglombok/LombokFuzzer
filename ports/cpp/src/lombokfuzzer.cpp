#include "lombokfuzzer.h"
namespace lombokfuzzer {
  uint64_t Prng::rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
  Prng::Prng(uint64_t seed) {
    uint64_t z = seed;
    for (int i = 0; i < 4; i++) {
      z += 0x9e3779b97f4a7c15ULL;
      z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
      z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
      s[i] = z ^ (z >> 31);
    }
  }
  uint64_t Prng::next() {
    uint64_t result = rotl(s[1] * 5, 7) * 9;
    uint64_t t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
    s[2] ^= t; s[3] = rotl(s[3], 45);
    return result;
  }
  int Prng::next_range(int n) { return n <= 0 ? 0 : static_cast<int>(next() % n); }
  std::vector<uint8_t> Prng::random_bytes(int n) {
    std::vector<uint8_t> buf(n);
    for (auto& b : buf) b = static_cast<uint8_t>(next());
    return buf;
  }
  uint64_t fnv1a64(const uint8_t* data, size_t len) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= 0x100000001b3ULL; }
    return h;
  }
}
