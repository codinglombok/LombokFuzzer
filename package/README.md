# LombokFuzzer

> Universal, multi-language, industry-grade fuzzing framework — part of the [Lombok Ecosystem](https://github.com/codinglombok).

[![CI](https://github.com/codinglombok/LombokFuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/codinglombok/LombokFuzzer/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![npm](https://img.shields.io/badge/npm-lombokfuzzer-red.svg)](https://www.npmjs.com/package/lombokfuzzer)
[![TypeScript](https://img.shields.io/badge/TypeScript-zero--dep%20core-3178c6.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/tests-41%20passing-brightgreen.svg)](./tests)

LombokFuzzer is a next-generation fuzzing framework built to be **language-portable**, **platform-agnostic**, and **industry-grade** — one engine covering software, firmware, network protocols, REST/GraphQL APIs, web applications, databases, and cryptographic primitives.

---

## Why another fuzzer?

| Gap in existing tools | LombokFuzzer answer |
|---|---|
| AFL / libFuzzer are C-only | Universal TypeScript core + native ports |
| No single tool covers all surfaces | One engine: software + hardware + protocol + API + web + SQL + crypto |
| Corpus corruption goes silent | Reed–Solomon integrity via [LombokECC](https://github.com/codinglombok) |
| Grammar fuzzers live separately | Integrated grammar engine (ABNF / PEG / JSON) |
| Limited scheduling research | 7 scheduling algorithms (MAB / rare-branch / Entropic / ECOFUZZ …) |
| Web fuzzers lack depth | DOM-aware + CSP + CORS + cookie + auth-state fuzzing |
| SQL injection tools are dated | AST-aware SQL mutation with per-dialect payloads |

## Standards alignment

The design maps to recognised software-assurance and safety standards: ISO/IEC 27034 (application security), IEC 62443 (industrial/OT), DO-178C & ISO 26262 (safety-critical avionics/automotive), OWASP ASVS/WSTG, NIST SP 800-115 & SP 800-22 (RNG statistical tests), IEEE 2851, and the CWE Top 25. See [`ARCHITECTURE.md`](./ARCHITECTURE.md).

---

## Install

```bash
npm install lombokfuzzer
```

Zero runtime dependencies. The ECC, dashboard, and chart integrations are **optional peer dependencies** — install them only if you use those features.

## Quick start — mutation fuzzing

```ts
import { LombokFuzzer, FuzzMode } from 'lombokfuzzer';

const fuzzer = new LombokFuzzer({
  name: 'json-parser',
  mode: FuzzMode.Mutation,
  maxExecutions: 100_000,
  harness: {
    mode: 'in_process',
    targetFunction: (data) => JSON.parse(new TextDecoder().decode(data)),
  },
});

// Seed the corpus
fuzzer.addSeed(new TextEncoder().encode('{"a":1}'));
fuzzer.addSeed(new TextEncoder().encode('[1,2,3]'));

fuzzer.on('crash_found', ({ crash }) => {
  console.log(`[${crash.severity}] ${crash.category} — ${crash.id}`);
});

const stats = await fuzzer.run();
console.log(`${stats.totalExecutions} execs, ${stats.uniqueCrashes} unique crashes`);
```

## Grammar-based generation

```ts
import { GrammarEngine, PRNG } from 'lombokfuzzer';

const engine = new GrammarEngine(new PRNG(42n));
const sql = engine.generate(GrammarEngine.sqlGrammar());
// → "SELECT * FROM users WHERE id = 42"
```

## Protocol fuzzing

```ts
import { ProtocolFuzzerRegistry, PRNG } from 'lombokfuzzer';

const prng = new PRNG(1n);
const registry = new ProtocolFuzzerRegistry();

const http = registry.get('HTTP')!;
let msg = http.generate(prng);   // valid-ish request
msg = http.mutate(msg, prng);    // now malformed — request smuggling, CRLF, etc.
```

## Web application scanning

```ts
import { WebFuzzer, PRNG } from 'lombokfuzzer';

const web = new WebFuzzer(new PRNG(7n));

const findings = web.analyzeSecurityHeaders('https://target.example', {
  'access-control-allow-origin': '*',
  'access-control-allow-credentials': 'true',
});
// → CORS misconfiguration (high), missing CSP, clickjacking, MIME sniffing

const xss = web.generateXSSPayloads('attribute');
```

## SQL injection

```ts
import { SQLFuzzer, SQLDialect, PRNG } from 'lombokfuzzer';

const sql = new SQLFuzzer(new PRNG(3n), SQLDialect.PostgreSQL);
const payloads = sql.generatePayloads('string', 20);
// tautology, union-based, error-based, time-based blind, stacked, WAF bypass…
```

## Cryptographic testing

```ts
import { CryptoFuzzer, PRNG } from 'lombokfuzzer';

const crypto = new CryptoFuzzer(new PRNG(9n));

// Detect timing side-channels in a comparison
const result = crypto.timingTest(myCompareFn, 32, 10_000);
console.log(result.verdict);

// NIST SP 800-22 subset RNG quality tests
const rng = crypto.testRNGQuality(() => Math.random(), 100_000);
```

## Hardware / firmware fuzzing

```ts
import { HardwareFuzzer, HWInterface, PRNG } from 'lombokfuzzer';

const hw = new HardwareFuzzer(new PRNG(5n));

const usb = hw.generateCommands({ interface: HWInterface.USB }, 100);
const regs = hw.generateRegisterFuzz({
  CONTROL: { address: 0x04, width: 32, access: 'rw', resetValue: 0 },
});
```

---

## Module map

```
src/
├── core/        FuzzEngine, config, event system, lifecycle
├── mutators/    14 strategies (bit-flip → structure-aware → token-level)
├── corpus/      dedup, minimization (set-cover), snapshots
├── coverage/    AFL-compatible edge bitmap, virgin bits, stability
├── crash/       stack parsing (Node/ASan/GDB), CWE classification, dedup
├── scheduler/   7 energy algorithms (RoundRobin, AFLFast, MAB, Entropic …)
├── grammar/     ABNF/PEG-style AST + built-in JSON/HTTP/SQL grammars
├── protocols/   HTTP, DNS, WebSocket wire-format fuzzers
├── api/         OpenAPI-driven REST fuzzing, auth-state, IDOR/mass-assign
├── web/         XSS, CSRF, CSP, CORS, cookie, security-header analysis
├── sql/         AST-aware injection, PG/MySQL/MSSQL/SQLite/Oracle dialects
├── crypto/      timing side-channel, padding oracle, RNG quality (SP 800-22)
├── hardware/    JTAG, SWD, UART, SPI, I2C, USB register/command fuzzing
└── utils/       xoshiro256** PRNG, FNV-1a / xxHash, stack hashing
```

## Build & test

```bash
npm run build      # tsc → dual CJS + ESM in dist/
npm test           # jest — 41 tests across all modules
npm run typecheck  # tsc --noEmit
```

---

## Roadmap

| Version | Scope |
|---|---|
| **v0.1.0** *(current)* | TypeScript core: engine, mutators, coverage, crash triage, grammar, protocol/API/web/SQL/crypto/hardware modules |
| v0.2.0 | ECC corpus integrity, HTML dashboard (LombokCharts + LombokCSS), CLI, reporters, differential oracle |
| v0.3.0 | Fork-server / network / WASM harnesses, sanitizer bridges, mobile (ADB/XCUITest) |
| v0.4.0+ | Language ports: Go, Rust, Python, C++, PHP, Java, Perl |
| v1.0.0 | Stabilised cross-language API, full standards-compliance attestation |

## License

Apache-2.0 © codinglombok. See [`LICENSE`](./LICENSE).
