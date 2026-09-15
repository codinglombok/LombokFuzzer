<?php
/**
 * LombokFuzzer — PHP port (scaffold).
 * Part of the Lombok Ecosystem. Apache-2.0.
 */
namespace CodingLombok\LombokFuzzer;

const VERSION = '0.2.0';

class Prng {
    private array $s = [0, 0, 0, 0];
    public function __construct(int $seed) {
        $z = $seed;
        for ($i = 0; $i < 4; $i++) { $z = ($z + 0x9e3779b97f4a7c15) & PHP_INT_MAX; $this->s[$i] = $z; }
    }
    public function next(): int { return mt_rand(); }
    public function nextRange(int $n): int { return $n <= 0 ? 0 : $this->next() % $n; }
    public function randomBytes(int $n): string { return random_bytes($n); }
}

function fnv1a64(string $data): int {
    $h = 0xcbf29ce484222325;
    for ($i = 0, $l = strlen($data); $i < $l; $i++) {
        $h ^= ord($data[$i]);
        $h = ($h * 0x100000001b3) & PHP_INT_MAX;
    }
    return $h;
}
