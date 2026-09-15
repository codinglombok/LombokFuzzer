package lombokfuzzer

import (
	"errors"
	"testing"
)

func TestPRNG(t *testing.T) {
	p := NewPRNG(42)
	v1 := p.Next()
	v2 := p.Next()
	if v1 == v2 {
		t.Error("PRNG should produce different values")
	}
	if v1 == 0 && v2 == 0 {
		t.Error("PRNG should not produce all zeros")
	}
}

func TestPRNGDeterministic(t *testing.T) {
	a := NewPRNG(123)
	b := NewPRNG(123)
	for i := 0; i < 100; i++ {
		if a.Next() != b.Next() {
			t.Fatalf("Same seed should produce same sequence at step %d", i)
		}
	}
}

func TestPRNGRange(t *testing.T) {
	p := NewPRNG(42)
	for i := 0; i < 1000; i++ {
		v := p.NextRange(10)
		if v < 0 || v >= 10 {
			t.Fatalf("NextRange(10) returned %d", v)
		}
	}
}

func TestFNV1a64(t *testing.T) {
	h1 := FNV1a64([]byte("hello"))
	h2 := FNV1a64([]byte("world"))
	h3 := FNV1a64([]byte("hello"))
	if h1 == h2 {
		t.Error("Different inputs should have different hashes")
	}
	if h1 != h3 {
		t.Error("Same input should have same hash")
	}
}

func TestCoverageTracker(t *testing.T) {
	ct := NewCoverageTracker(1024)
	if ct.EdgesFound() != 0 {
		t.Error("New tracker should have 0 edges")
	}
	isNew := ct.RecordEdge(1, 2)
	if !isNew {
		t.Error("First edge should be new")
	}
	if ct.EdgesFound() != 1 {
		t.Errorf("Expected 1 edge, got %d", ct.EdgesFound())
	}
	isNew2 := ct.RecordEdge(1, 2)
	if isNew2 {
		t.Error("Same edge should not be new")
	}
	ct.Reset()
	if ct.EdgesFound() != 0 {
		t.Error("Reset should clear edges")
	}
}

func TestMutatorEngine(t *testing.T) {
	prng := NewPRNG(42)
	me := NewMutatorEngine(prng)

	data := []byte("hello world test input")
	mutated := me.Mutate(data)
	if len(mutated) == 0 {
		t.Error("Mutation should produce non-empty output")
	}

	// Empty input should produce random bytes
	empty := me.Mutate([]byte{})
	if len(empty) == 0 {
		t.Error("Empty input mutation should produce random bytes")
	}
}

func TestCorpusStore(t *testing.T) {
	cs := NewCorpusStore()
	if cs.Size() != 0 {
		t.Error("New corpus should be empty")
	}
	input := &FuzzInput{Data: []byte("test"), Hash: FNV1a64([]byte("test"))}
	added := cs.Add(input)
	if !added {
		t.Error("First add should succeed")
	}
	if cs.Size() != 1 {
		t.Errorf("Expected size 1, got %d", cs.Size())
	}
	dup := cs.Add(input)
	if dup {
		t.Error("Duplicate should not be added")
	}

	prng := NewPRNG(42)
	picked := cs.Pick(prng)
	if picked == nil {
		t.Error("Pick should return an entry")
	}
}

func TestCrashAnalyzer(t *testing.T) {
	ca := NewCrashAnalyzer()
	input := &FuzzInput{Data: []byte("crash"), Hash: 123}
	err := errors.New("segfault")

	isUnique := ca.Record(input, err)
	if !isUnique {
		t.Error("First crash should be unique")
	}
	if ca.UniqueCount() != 1 {
		t.Errorf("Expected 1 unique crash, got %d", ca.UniqueCount())
	}

	isDup := ca.Record(input, err)
	if isDup {
		t.Error("Same error should be duplicate")
	}

	isUnique2 := ca.Record(input, errors.New("different error"))
	if !isUnique2 {
		t.Error("Different error should be unique")
	}
}

func TestFuzzEngine(t *testing.T) {
	crashCount := 0
	engine := New(FuzzConfig{
		Name:          "test-campaign",
		Mode:          ModeMutation,
		Seed:          42,
		MaxExecutions: 1000,
		TargetFunc: func(data []byte) error {
			if len(data) > 3 && data[0] == 0xFF && data[1] == 0xFE {
				crashCount++
				return errors.New("buffer overflow")
			}
			return nil
		},
	})

	stats := engine.Run()
	if stats.TotalExecutions != 1000 {
		t.Errorf("Expected 1000 executions, got %d", stats.TotalExecutions)
	}
	if stats.CorpusSize == 0 {
		t.Error("Corpus should have entries")
	}
}

func TestFuzzEngineStop(t *testing.T) {
	engine := New(FuzzConfig{
		Name:          "stop-test",
		Seed:          42,
		MaxExecutions: 0, // unlimited
		TargetFunc:    func(data []byte) error { return nil },
	})

	done := make(chan FuzzStats)
	go func() {
		done <- engine.Run()
	}()

	// Stop after a short delay
	go func() {
		<-make(chan struct{}) // small yield
		engine.Stop()
	}()

	// Should complete eventually
	engine.Stop()
	<-done
}
