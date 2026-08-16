package cli

// Tests for addCollector behavior.
//
// The invariants we care about:
//
//  1. WITHOUT --full: the live aggregating collector is always active (updates ≠ nil,
//     live display and autoterm work); per-transaction ops are NOT stored (retrieveOps
//     returns empty), so no trace.tsv.zst is written.
//
//  2. WITH --full + streaming writer: the live aggregating collector is ALSO active
//     (updates ≠ nil, live display and autoterm still work); per-transaction ops ARE
//     streamed to .trace.tsv.zst. --full is additive.
//
//  3. DiscardOutput=true: both retrieveOps and updates are nil/empty regardless of --full.

import (
	"context"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	mcli "github.com/minio/cli"
	"github.com/minio/warp/pkg/aggregate"
	"github.com/minio/warp/pkg/bench"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// stubBench is the minimal bench.Benchmark stub needed by addCollector.
// It only needs GetCommon(); the other methods are never called in tests.
type stubBench struct {
	bench.Common
}

func (s *stubBench) Prepare(_ context.Context) error                { return nil }
func (s *stubBench) Start(_ context.Context, _ chan struct{}) error { return nil }
func (s *stubBench) Cleanup(_ context.Context)                      {}

// makeCtx builds a *cli.Context with only the flags addCollector reads.
func makeCtx(full bool) *mcli.Context {
	app := mcli.NewApp()
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.Bool("full", full, "")
	return mcli.NewContext(app, set, nil)
}

// sendOp sends a single representative operation to the collector and returns it.
func sendOp(t *testing.T, c bench.Collector) bench.Operation {
	t.Helper()
	now := time.Now()
	op := bench.Operation{
		OpType: "GET",
		Start:  now,
		End:    now.Add(time.Millisecond),
		Size:   1024,
		Thread: 0,
	}
	c.Receiver() <- op
	return op
}

// requestFinal asks the live collector for its final aggregate (blocking).
func requestFinal(t *testing.T, updates chan<- aggregate.UpdateReq) *aggregate.Realtime {
	t.Helper()
	ch := make(chan *aggregate.Realtime, 1)
	updates <- aggregate.UpdateReq{Final: true, C: ch}
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for final aggregate from updates channel")
		return nil
	}
}

// ---------------------------------------------------------------------------
// Test 1: default mode (no --full)
// ---------------------------------------------------------------------------

// Without --full:
//   - updates must be non-nil  (live display / autoterm work)
//   - retrieveOps must return empty  (no per-transaction recording → no trace.tsv.zst)
func TestAddCollector_DefaultMode_NoOpsStored(t *testing.T) {
	ctx := makeCtx(false)
	b := &stubBench{}

	retrieveOps, updates := addCollector(ctx, b)

	// updates must be non-nil so live display and autoterm remain functional.
	if updates == nil {
		t.Fatal("expected non-nil updates channel in default (no --full) mode")
	}

	// Send an operation to the collector and close it.
	sendOp(t, b.Collector)
	b.Collector.Close()

	// Without --full, retrieveOps is EmptyOpsCollector → must return empty.
	ops := retrieveOps()
	if len(ops) != 0 {
		t.Errorf("expected 0 ops from retrieveOps in default mode, got %d", len(ops))
	}
}

// ---------------------------------------------------------------------------
// Test 2: --full mode without streaming writer — live-only, no in-memory ops
// ---------------------------------------------------------------------------

// With --full but no streaming writer, addCollector falls through to the
// live-only default path: updates is non-nil, retrieveOps returns 0 ops.
func TestAddCollector_FullMode_OpsAreCollected(t *testing.T) {
	ctx := makeCtx(true)
	b := &stubBench{}

	retrieveOps, updates := addCollector(ctx, b)

	// updates must be non-nil even in --full mode.
	if updates == nil {
		t.Fatal("expected non-nil updates channel in --full mode")
	}

	const numOps = 5
	for i := 0; i < numOps; i++ {
		sendOp(t, b.Collector)
	}
	b.Collector.Close()

	// No streaming writer → live-only, no in-memory accumulation.
	ops := retrieveOps()
	if len(ops) != 0 {
		t.Errorf("live-only --full: expected 0 in-memory ops, got %d", len(ops))
	}
}

// ---------------------------------------------------------------------------
// Test 3: --full mode — live collector receives ops (live-only path)
// ---------------------------------------------------------------------------

// With --full but no streaming writer, the live collector is the sole
// collector. After closing, the live aggregate must reflect the sent ops.
func TestAddCollector_FullMode_LiveCollectorAlsoReceivesOps(t *testing.T) {
	ctx := makeCtx(true)
	b := &stubBench{}

	_, updates := addCollector(ctx, b)

	const numOps = 3
	for i := 0; i < numOps; i++ {
		sendOp(t, b.Collector)
	}
	b.Collector.Close()

	// Live collector must have received the ops.
	final := requestFinal(t, updates)
	if final == nil {
		t.Fatal("final aggregate is nil; live collector did not receive ops")
	}
	if final.Total.TotalRequests == 0 {
		t.Errorf("live collector TotalRequests == 0; ops were not forwarded to the live collector")
	}
}

// ---------------------------------------------------------------------------
// Test 4: default mode — updates channel is writable (live collector active)
// ---------------------------------------------------------------------------

// Without --full the live collector is the sole collector.
// Verify the updates channel remains available after collector shutdown.
func TestAddCollector_DefaultMode_UpdatesChannelFunctional(t *testing.T) {
	ctx := makeCtx(false)
	b := &stubBench{}

	_, updates := addCollector(ctx, b)

	if updates == nil {
		t.Fatal("expected non-nil updates channel in default mode")
	}

	// Send ops then close.
	const numOps = 4
	for i := 0; i < numOps; i++ {
		sendOp(t, b.Collector)
	}
	b.Collector.Close()

	// The updates channel is buffered (capacity 1000); a write must not block.
	// A Reset request is a no-op for the live collector and safe to use here.
	select {
	case updates <- aggregate.UpdateReq{Reset: true}:
		// Channel is live and accepting writes.
	default:
		t.Fatal("updates channel blocked unexpectedly")
	}
}

// ---------------------------------------------------------------------------
// Test 5: DiscardOutput=true always suppresses collection
// ---------------------------------------------------------------------------

// When DiscardOutput is true, both retrieveOps and updates must be nil/empty.
// This is the "silent / terse run" mode used in distributed client mode.
func TestAddCollector_DiscardOutput_NullCollector(t *testing.T) {
	// DiscardOutput with --full=false
	t.Run("full=false", func(t *testing.T) {
		ctx := makeCtx(false)
		b := &stubBench{}
		b.DiscardOutput = true

		retrieveOps, updates := addCollector(ctx, b)

		if updates != nil {
			t.Error("expected nil updates when DiscardOutput=true and full=false")
		}
		ops := retrieveOps()
		if len(ops) != 0 {
			t.Errorf("expected 0 ops when DiscardOutput=true and full=false, got %d", len(ops))
		}
	})

	// DiscardOutput with --full=true (--full must not override DiscardOutput)
	t.Run("full=true", func(t *testing.T) {
		ctx := makeCtx(true)
		b := &stubBench{}
		b.DiscardOutput = true

		retrieveOps, updates := addCollector(ctx, b)

		if updates != nil {
			t.Error("expected nil updates when DiscardOutput=true even with --full")
		}
		ops := retrieveOps()
		if len(ops) != 0 {
			t.Errorf("expected 0 ops when DiscardOutput=true even with --full, got %d", len(ops))
		}
	})
}

// ---------------------------------------------------------------------------
// Test 6: --full is ADDITIVE — both outputs work when streaming writer provided
// ---------------------------------------------------------------------------

// This test validates the core contract: when --full is set WITH a streaming
// writer, ops flow to the file AND the live aggregate is also populated.
func TestAddCollector_FullMode_IsAdditive(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/additive.trace.tsv.zst"

	csvWriter, err := bench.NewStreamingOpsWriter(path, "testID", "")
	if err != nil {
		t.Fatalf("NewStreamingOpsWriter: %v", err)
	}

	ctx := makeCtx(true)
	b := &stubBench{}

	retrieveOps, updates := addCollector(ctx, b, csvWriter.Receiver())

	// Both must be non-nil immediately after addCollector returns.
	if updates == nil {
		t.Fatal("updates must be non-nil with --full (live display required)")
	}

	// Send ops.
	const numOps = 6
	for i := 0; i < numOps; i++ {
		sendOp(t, b.Collector)
	}
	b.Collector.Close()
	if werr := csvWriter.Wait(); werr != nil {
		t.Fatalf("csvWriter.Wait: %v", werr)
	}

	// Streaming mode: no in-memory accumulation.
	ops := retrieveOps()
	if len(ops) != 0 {
		t.Errorf("expected 0 in-memory ops in streaming mode, got %d", len(ops))
	}

	// Live aggregate must also be non-empty (additive, not replacing).
	final := requestFinal(t, updates)
	if final == nil {
		t.Fatal("live aggregate is nil; --full must not disable the live collector")
	}
	if final.Total.TotalRequests == 0 {
		t.Errorf("live aggregate TotalRequests == 0; --full must not disable the live collector")
	}
}

// ---------------------------------------------------------------------------
// Test 7: ops correctness — values are preserved through the streaming writer
// ---------------------------------------------------------------------------

// With --full + streaming writer, the ops written to the file must be the
// exact operations that were sent — no data loss through the fan-out path.
func TestAddCollector_FullMode_OpValuesPreserved(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ops.trace.tsv.zst"

	csvWriter, err := bench.NewStreamingOpsWriter(path, "valID", "")
	if err != nil {
		t.Fatalf("NewStreamingOpsWriter: %v", err)
	}

	ctx := makeCtx(true)
	b := &stubBench{}

	_, _ = addCollector(ctx, b, csvWriter.Receiver())

	now := time.Now().Truncate(time.Millisecond)
	op := bench.Operation{
		OpType: "PUT",
		Start:  now,
		End:    now.Add(42 * time.Millisecond),
		Size:   8192,
		Thread: 3,
	}
	b.Collector.Receiver() <- op
	b.Collector.Close()
	if werr := csvWriter.Wait(); werr != nil {
		t.Fatalf("csvWriter.Wait: %v", werr)
	}

	// Read back from file to verify value preservation.
	f, ferr := os.Open(path)
	if ferr != nil {
		t.Fatalf("open %s: %v", path, ferr)
	}
	defer f.Close()
	dec, derr := zstd.NewReader(f)
	if derr != nil {
		t.Fatalf("zstd.NewReader: %v", derr)
	}
	defer dec.Close()
	ops, rerr := bench.OperationsFromCSV(dec, false, 0, 0, func(string, ...any) {})
	if rerr != nil {
		t.Fatalf("OperationsFromCSV: %v", rerr)
	}
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	got := ops[0]
	if got.OpType != op.OpType {
		t.Errorf("OpType: got %q want %q", got.OpType, op.OpType)
	}
	if !got.Start.Equal(op.Start) {
		t.Errorf("Start: got %v want %v", got.Start, op.Start)
	}
	if !got.End.Equal(op.End) {
		t.Errorf("End: got %v want %v", got.End, op.End)
	}
	if got.Size != op.Size {
		t.Errorf("Size: got %d want %d", got.Size, op.Size)
	}
	if got.Thread != op.Thread {
		t.Errorf("Thread: got %d want %d", got.Thread, op.Thread)
	}
}

// ---------------------------------------------------------------------------
// Stage 2 tests: streaming mode via addCollector's fullExtra parameter
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 8: streaming mode — ops go to the channel, not to in-memory store
// ---------------------------------------------------------------------------

// When a streaming channel is passed to addCollector and --full is set:
//   - retrieveOps must return empty (ops are streamed, not buffered in RAM)
//   - the streaming channel must receive every op
func TestAddCollector_StreamingMode_OpsGoToChannel(t *testing.T) {
	ctx := makeCtx(true) // --full

	streamCh := make(chan bench.Operation, 100)
	b := &stubBench{}

	retrieveOps, updates := addCollector(ctx, b, streamCh)
	if updates == nil {
		t.Fatal("expected non-nil updates in streaming mode")
	}

	const numOps = 8
	for i := 0; i < numOps; i++ {
		sendOp(t, b.Collector)
	}
	// Collector.Close() closes streamCh (it is in the fan-out extra list).
	b.Collector.Close()

	// In streaming mode, retrieveOps must return empty (no in-memory accumulation).
	ops := retrieveOps()
	if len(ops) != 0 {
		t.Errorf("streaming mode: expected 0 in-memory ops, got %d", len(ops))
	}

	// All ops must have arrived on the streaming channel.
	var received int
	for range streamCh {
		received++
	}
	if received != numOps {
		t.Errorf("streaming channel: expected %d ops, got %d", numOps, received)
	}
}

// ---------------------------------------------------------------------------
// Test 9: streaming mode — live collector still receives every op
// ---------------------------------------------------------------------------

// --full with streaming must be additive: both the streaming channel AND the
// live aggregate collector receive every op.
func TestAddCollector_StreamingMode_LiveCollectorAlsoReceives(t *testing.T) {
	ctx := makeCtx(true)

	streamCh := make(chan bench.Operation, 100)
	b := &stubBench{}

	_, updates := addCollector(ctx, b, streamCh)

	const numOps = 5
	for i := 0; i < numOps; i++ {
		sendOp(t, b.Collector)
	}
	b.Collector.Close()

	// Drain streaming channel so the test doesn't block.
	var streamed int
	for range streamCh {
		streamed++
	}
	if streamed != numOps {
		t.Errorf("streaming channel: expected %d ops, got %d", numOps, streamed)
	}

	// Live collector must also have received all ops.
	final := requestFinal(t, updates)
	if final == nil {
		t.Fatal("live aggregate is nil; streaming mode must not disable live collector")
	}
	if final.Total.TotalRequests == 0 {
		t.Errorf("live TotalRequests == 0; ops were not forwarded to live collector in streaming mode")
	}
}

// ---------------------------------------------------------------------------
// Test 10: full mode with no streaming channel falls through to live-only
// ---------------------------------------------------------------------------

// Passing no fullExtra channel with --full falls through to live-only default.
// retrieveOps always returns empty (no in-memory accumulation).
func TestAddCollector_FullMode_NoChannel_LiveOnly(t *testing.T) {
	ctx := makeCtx(true)
	b := &stubBench{}

	// No extra channel → live-only (batch fallback removed).
	retrieveOps, updates := addCollector(ctx, b)
	if updates == nil {
		t.Fatal("expected non-nil updates channel")
	}

	const numOps = 4
	for i := 0; i < numOps; i++ {
		sendOp(t, b.Collector)
	}
	b.Collector.Close()

	// No in-memory accumulation in this path.
	ops := retrieveOps()
	if len(ops) != 0 {
		t.Errorf("live-only: expected 0 in-memory ops, got %d", len(ops))
	}
}

// ---------------------------------------------------------------------------
// Test 11: end-to-end — streaming path writes correct trace.tsv.zst file
// ---------------------------------------------------------------------------

// Full pipeline: addCollector with a StreamingOpsWriter → send ops → close
// collector (which closes writer channel) → wait writer → read back file.
func TestAddCollector_Streaming_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/out.trace.tsv.zst"
	const wantClientID = "e2eID"

	csvWriter, err := bench.NewStreamingOpsWriter(path, wantClientID, "")
	if err != nil {
		t.Fatalf("NewStreamingOpsWriter: %v", err)
	}

	ctx := makeCtx(true)
	b := &stubBench{}

	retrieveOps, updates := addCollector(ctx, b, csvWriter.Receiver())
	if updates == nil {
		t.Fatal("expected non-nil updates in streaming end-to-end test")
	}

	const numOps = 12
	now := time.Now().Truncate(time.Millisecond)
	for i := 0; i < numOps; i++ {
		b.Collector.Receiver() <- bench.Operation{
			OpType: "GET",
			Thread: uint32(i % 4),
			Start:  now,
			End:    now.Add(time.Duration(i+1) * time.Millisecond),
			Size:   int64(1024 * (i + 1)),
		}
	}
	// Collector.Close() closes csvWriter.Receiver() as an extra channel.
	b.Collector.Close()

	// Streaming mode: no in-memory ops.
	ops := retrieveOps()
	if len(ops) != 0 {
		t.Errorf("expected 0 in-memory ops in streaming mode, got %d", len(ops))
	}

	// Wait for writer to flush to disk.
	if err := csvWriter.Wait(); err != nil {
		t.Fatalf("csvWriter.Wait: %v", err)
	}

	// Read back and validate.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open csv file: %v", err)
	}
	defer f.Close()

	dec, err := zstd.NewReader(f)
	if err != nil {
		t.Fatalf("zstd.NewReader: %v", err)
	}
	defer dec.Close()

	written, err := bench.OperationsFromCSV(dec, false, 0, 0, func(string, ...any) {})
	if err != nil {
		t.Fatalf("OperationsFromCSV: %v", err)
	}
	if len(written) != numOps {
		t.Errorf("csv file: expected %d ops, got %d", numOps, len(written))
	}
	for i, op := range written {
		if op.ClientID != wantClientID {
			t.Errorf("op[%d] ClientID: got %q, want %q", i, op.ClientID, wantClientID)
		}
	}
}

func TestFinalizeCollector_WaitsForStreamingWriter(t *testing.T) {
	path := t.TempDir() + "/finalized.trace.tsv.zst"
	w, err := bench.NewStreamingOpsWriter(path, "finalID", "")
	if err != nil {
		t.Fatalf("NewStreamingOpsWriter: %v", err)
	}
	collector := bench.NewNullCollector(w.Receiver())
	collector.Receiver() <- bench.Operation{
		OpType: "GET",
		Start:  time.Now(),
		End:    time.Now().Add(time.Millisecond),
		Size:   1024,
	}

	if err := finalizeCollector(collector, w); err != nil {
		t.Fatalf("finalizeCollector: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open finalized trace: %v", err)
	}
	defer f.Close()
	dec, err := zstd.NewReader(f)
	if err != nil {
		t.Fatalf("zstd.NewReader: %v", err)
	}
	defer dec.Close()
	ops, err := bench.OperationsFromCSV(dec, false, 0, 0, t.Logf)
	if err != nil {
		t.Fatalf("OperationsFromCSV: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("expected 1 finalized operation, got %d", len(ops))
	}
}
