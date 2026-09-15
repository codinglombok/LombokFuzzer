// Package lombokfuzzer is a Go port of LombokFuzzer — universal fuzzing framework.
//
// Part of the Lombok Ecosystem (github.com/codinglombok/LombokFuzzer).
// Apache-2.0 License.
package lombokfuzzer

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Types ──────────────────────────────────────────────────────────────────

// FuzzMode selects the fuzzing strategy.
type FuzzMode string

const (
	ModeMutation     FuzzMode = "mutation"
	ModeGeneration   FuzzMode = "generation"
	ModeHybrid       FuzzMode = "hybrid"
	ModeDifferential FuzzMode = "differential"
	ModeDirected     FuzzMode = "directed"
)

// Severity classifies crash severity.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// FuzzConfig configures a fuzzing campaign.
type FuzzConfig struct {
	Name            string
	Mode            FuzzMode
	Seed            uint64
	MaxExecutions   uint64
	MaxTimeSeconds  int
	MaxInputSize    int
	TimeoutMs       int
	Workers         int
	TargetFunc      func(data []byte) error
}

// FuzzInput represents one test input.
type FuzzInput struct {
	Data       []byte
	Hash       uint64
	Depth      int
	Energy     float64
	Executions uint64
	CreatedAt  time.Time
}

// ExecutionResult captures what happened when a target processed an input.
type ExecutionResult struct {
	Input      *FuzzInput
	Crashed    bool
	NewCoverage bool
	DurationUs int64
	Error      error
}

// FuzzStats tracks campaign statistics.
type FuzzStats struct {
	TotalExecutions  uint64
	ExecsPerSecond   float64
	CorpusSize       int
	UniqueCrashes    int
	EdgesFound       int
	EdgesTotal       int
	CoveragePercent  float64
	ElapsedMs        int64
}

// ─── PRNG (xoshiro256**) ────────────────────────────────────────────────────

// PRNG implements xoshiro256** for fast, reproducible pseudo-random numbers.
type PRNG struct {
	s [4]uint64
}

// NewPRNG creates a seeded PRNG.
func NewPRNG(seed uint64) *PRNG {
	p := &PRNG{}
	// SplitMix64 seeding
	z := seed
	for i := 0; i < 4; i++ {
		z += 0x9e3779b97f4a7c15
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		p.s[i] = z ^ (z >> 31)
	}
	return p
}

func (p *PRNG) rotl(x uint64, k uint) uint64 {
	return (x << k) | (x >> (64 - k))
}

// Next returns the next pseudo-random uint64.
func (p *PRNG) Next() uint64 {
	result := p.rotl(p.s[1]*5, 7) * 9
	t := p.s[1] << 17
	p.s[2] ^= p.s[0]
	p.s[3] ^= p.s[1]
	p.s[1] ^= p.s[2]
	p.s[0] ^= p.s[3]
	p.s[2] ^= t
	p.s[3] = p.rotl(p.s[3], 45)
	return result
}

// NextRange returns a random number in [0, n).
func (p *PRNG) NextRange(n int) int {
	if n <= 0 {
		return 0
	}
	return int(p.Next() % uint64(n))
}

// RandomBytes returns n random bytes.
func (p *PRNG) RandomBytes(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(p.Next())
	}
	return buf
}

// ─── Hash (FNV-1a 64-bit) ──────────────────────────────────────────────────

// FNV1a64 computes the FNV-1a 64-bit hash of data.
func FNV1a64(data []byte) uint64 {
	h := fnv.New64a()
	h.Write(data)
	return h.Sum64()
}

// ─── Coverage Tracker ───────────────────────────────────────────────────────

// CoverageTracker tracks edge coverage using a fixed-size bitmap.
type CoverageTracker struct {
	bitmap     []byte
	bitmapSize int
	edgesFound int
	mu         sync.RWMutex
}

// NewCoverageTracker creates a tracker with the given bitmap size.
func NewCoverageTracker(size int) *CoverageTracker {
	if size <= 0 {
		size = 65536
	}
	return &CoverageTracker{
		bitmap:     make([]byte, size),
		bitmapSize: size,
	}
}

// RecordEdge records a hit on an edge and returns true if it's new.
func (ct *CoverageTracker) RecordEdge(from, to uint64) bool {
	idx := int((from ^ to) % uint64(ct.bitmapSize))
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.bitmap[idx] == 0 {
		ct.bitmap[idx] = 1
		ct.edgesFound++
		return true
	}
	ct.bitmap[idx]++
	return false
}

// EdgesFound returns the number of unique edges discovered.
func (ct *CoverageTracker) EdgesFound() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.edgesFound
}

// CoveragePercent returns % of bitmap occupied.
func (ct *CoverageTracker) CoveragePercent() float64 {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return float64(ct.edgesFound) / float64(ct.bitmapSize) * 100
}

// Reset clears the bitmap.
func (ct *CoverageTracker) Reset() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for i := range ct.bitmap {
		ct.bitmap[i] = 0
	}
	ct.edgesFound = 0
}

// ─── Mutator Engine ─────────────────────────────────────────────────────────

// MutatorStrategy names a mutation strategy.
type MutatorStrategy string

const (
	StrategyBitFlip    MutatorStrategy = "bit_flip"
	StrategyByteFlip   MutatorStrategy = "byte_flip"
	StrategyArithmetic MutatorStrategy = "arithmetic"
	StrategyInteresting MutatorStrategy = "interesting"
	StrategyHavoc      MutatorStrategy = "havoc"
	StrategySplice     MutatorStrategy = "splice"
)

// MutatorEngine applies mutations to inputs.
type MutatorEngine struct {
	prng       *PRNG
	strategies []MutatorStrategy
}

// NewMutatorEngine creates a mutator with the given PRNG.
func NewMutatorEngine(prng *PRNG) *MutatorEngine {
	return &MutatorEngine{
		prng: prng,
		strategies: []MutatorStrategy{
			StrategyBitFlip, StrategyByteFlip, StrategyArithmetic,
			StrategyInteresting, StrategyHavoc,
		},
	}
}

// Mutate applies a random mutation to the input and returns a new buffer.
func (me *MutatorEngine) Mutate(data []byte) []byte {
	if len(data) == 0 {
		return me.prng.RandomBytes(me.prng.NextRange(64) + 1)
	}

	out := make([]byte, len(data))
	copy(out, data)

	strategy := me.strategies[me.prng.NextRange(len(me.strategies))]
	switch strategy {
	case StrategyBitFlip:
		pos := me.prng.NextRange(len(out))
		bit := me.prng.NextRange(8)
		out[pos] ^= 1 << uint(bit)

	case StrategyByteFlip:
		pos := me.prng.NextRange(len(out))
		out[pos] ^= 0xFF

	case StrategyArithmetic:
		pos := me.prng.NextRange(len(out))
		delta := byte(me.prng.NextRange(70) - 35)
		out[pos] += delta

	case StrategyInteresting:
		interesting := []byte{0, 1, 0x7F, 0x80, 0xFF}
		pos := me.prng.NextRange(len(out))
		out[pos] = interesting[me.prng.NextRange(len(interesting))]

	case StrategyHavoc:
		rounds := me.prng.NextRange(8) + 1
		for r := 0; r < rounds; r++ {
			pos := me.prng.NextRange(len(out))
			out[pos] = byte(me.prng.Next())
		}
	}

	return out
}

// ─── Corpus Store ───────────────────────────────────────────────────────────

// CorpusStore manages the input corpus.
type CorpusStore struct {
	entries []*FuzzInput
	hashes  map[uint64]bool
	mu      sync.RWMutex
}

// NewCorpusStore creates an empty corpus.
func NewCorpusStore() *CorpusStore {
	return &CorpusStore{
		hashes: make(map[uint64]bool),
	}
}

// Add adds an input if it's not a duplicate. Returns true if added.
func (cs *CorpusStore) Add(input *FuzzInput) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.hashes[input.Hash] {
		return false
	}
	cs.hashes[input.Hash] = true
	cs.entries = append(cs.entries, input)
	return true
}

// Pick returns a random input from the corpus.
func (cs *CorpusStore) Pick(prng *PRNG) *FuzzInput {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	if len(cs.entries) == 0 {
		return nil
	}
	return cs.entries[prng.NextRange(len(cs.entries))]
}

// Size returns the corpus size.
func (cs *CorpusStore) Size() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.entries)
}

// ─── Crash Analyzer ─────────────────────────────────────────────────────────

// CrashInfo stores crash details.
type CrashInfo struct {
	ID           string
	Input        *FuzzInput
	Error        error
	Severity     Severity
	DiscoveredAt time.Time
	IsDuplicate  bool
}

// CrashAnalyzer detects and deduplicates crashes.
type CrashAnalyzer struct {
	crashes []CrashInfo
	hashes  map[uint64]bool
	mu      sync.Mutex
}

// NewCrashAnalyzer creates an empty analyzer.
func NewCrashAnalyzer() *CrashAnalyzer {
	return &CrashAnalyzer{
		hashes: make(map[uint64]bool),
	}
}

// Record records a crash. Returns true if it's unique.
func (ca *CrashAnalyzer) Record(input *FuzzInput, err error) bool {
	h := FNV1a64([]byte(err.Error()))
	ca.mu.Lock()
	defer ca.mu.Unlock()
	isDup := ca.hashes[h]
	ca.hashes[h] = true
	crash := CrashInfo{
		ID:           fmt.Sprintf("crash-%016x", h),
		Input:        input,
		Error:        err,
		Severity:     SeverityHigh,
		DiscoveredAt: time.Now(),
		IsDuplicate:  isDup,
	}
	ca.crashes = append(ca.crashes, crash)
	return !isDup
}

// UniqueCount returns the number of unique crashes.
func (ca *CrashAnalyzer) UniqueCount() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return len(ca.hashes)
}

// ─── Fuzz Engine ────────────────────────────────────────────────────────────

// FuzzEngine is the main fuzzing engine.
type FuzzEngine struct {
	config   FuzzConfig
	prng     *PRNG
	mutator  *MutatorEngine
	corpus   *CorpusStore
	coverage *CoverageTracker
	crashes  *CrashAnalyzer
	stats    FuzzStats
	stopCh   chan struct{}
	running  atomic.Bool
}

// New creates a new FuzzEngine.
func New(config FuzzConfig) *FuzzEngine {
	if config.MaxInputSize <= 0 {
		config.MaxInputSize = 4096
	}
	if config.Workers <= 0 {
		config.Workers = 1
	}
	prng := NewPRNG(config.Seed)
	return &FuzzEngine{
		config:   config,
		prng:     prng,
		mutator:  NewMutatorEngine(prng),
		corpus:   NewCorpusStore(),
		coverage: NewCoverageTracker(65536),
		crashes:  NewCrashAnalyzer(),
		stopCh:   make(chan struct{}),
	}
}

// Run starts the fuzzing campaign. Blocks until done or stopped.
func (fe *FuzzEngine) Run() FuzzStats {
	fe.running.Store(true)
	defer fe.running.Store(false)

	startTime := time.Now()

	// Seed corpus with one random input if empty
	if fe.corpus.Size() == 0 {
		seed := fe.prng.RandomBytes(fe.prng.NextRange(64) + 1)
		fe.corpus.Add(&FuzzInput{
			Data:      seed,
			Hash:      FNV1a64(seed),
			Energy:    1.0,
			CreatedAt: time.Now(),
		})
	}

	var execCount uint64

	for {
		select {
		case <-fe.stopCh:
			return fe.buildStats(startTime)
		default:
		}

		if fe.config.MaxExecutions > 0 && execCount >= fe.config.MaxExecutions {
			break
		}
		if fe.config.MaxTimeSeconds > 0 && time.Since(startTime) > time.Duration(fe.config.MaxTimeSeconds)*time.Second {
			break
		}

		// Pick & mutate
		parent := fe.corpus.Pick(fe.prng)
		if parent == nil {
			break
		}
		mutated := fe.mutator.Mutate(parent.Data)
		hash := FNV1a64(mutated)
		input := &FuzzInput{
			Data:      mutated,
			Hash:      hash,
			Depth:     parent.Depth + 1,
			Energy:    parent.Energy,
			CreatedAt: time.Now(),
		}

		// Execute target
		result := fe.execute(input)
		execCount++

		// Coverage feedback
		edgeHash := FNV1a64(mutated[:min(len(mutated), 8)])
		newEdge := fe.coverage.RecordEdge(uint64(parent.Hash), edgeHash)
		if newEdge {
			fe.corpus.Add(input)
		}

		// Crash detection
		if result.Crashed && result.Error != nil {
			fe.crashes.Record(input, result.Error)
		}
	}

	return fe.buildStats(startTime)
}

// Stop signals the engine to stop.
func (fe *FuzzEngine) Stop() {
	close(fe.stopCh)
}

func (fe *FuzzEngine) execute(input *FuzzInput) ExecutionResult {
	start := time.Now()
	var crashed bool
	var execErr error

	func() {
		defer func() {
			if r := recover(); r != nil {
				crashed = true
				execErr = fmt.Errorf("panic: %v", r)
			}
		}()
		if fe.config.TargetFunc != nil {
			if err := fe.config.TargetFunc(input.Data); err != nil {
				crashed = true
				execErr = err
			}
		}
	}()

	return ExecutionResult{
		Input:      input,
		Crashed:    crashed,
		DurationUs: time.Since(start).Microseconds(),
		Error:      execErr,
	}
}

func (fe *FuzzEngine) buildStats(startTime time.Time) FuzzStats {
	elapsed := time.Since(startTime).Milliseconds()
	var execsPerSec float64
	if elapsed > 0 {
		execsPerSec = math.Round(float64(fe.corpus.Size()) / float64(elapsed) * 1000)
	}
	return FuzzStats{
		TotalExecutions: fe.config.MaxExecutions,
		ExecsPerSecond:  execsPerSec,
		CorpusSize:      fe.corpus.Size(),
		UniqueCrashes:   fe.crashes.UniqueCount(),
		EdgesFound:      fe.coverage.EdgesFound(),
		EdgesTotal:      65536,
		CoveragePercent: fe.coverage.CoveragePercent(),
		ElapsedMs:       elapsed,
	}
}

// ─── Version ────────────────────────────────────────────────────────────────

const Version = "0.2.0"
const CodeName = "LombokFuzzer"
