#include "lombokfuzzer.h"
#include <cassert>
#include <cstdio>
int main() {
  lombokfuzzer::Prng a(42), b(42);
  for (int i = 0; i < 100; i++) assert(a.next() == b.next());
  auto bytes = lombokfuzzer::Prng(1).random_bytes(16);
  assert(bytes.size() == 16);
  uint8_t d1[] = {'h','e','l','l','o'};
  uint8_t d2[] = {'w','o','r','l','d'};
  assert(lombokfuzzer::fnv1a64(d1, 5) != lombokfuzzer::fnv1a64(d2, 5));
  assert(lombokfuzzer::fnv1a64(d1, 5) == lombokfuzzer::fnv1a64(d1, 5));
  printf("C++ port: all tests passed\n");
  return 0;
}
