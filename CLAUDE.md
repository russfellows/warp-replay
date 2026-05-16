# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Warp is a high-performance S3 benchmarking tool for testing object storage systems. It supports multiple benchmark types (GET, PUT, DELETE, LIST, STAT, etc.) and can run in distributed mode with multiple clients coordinating through a server.

## Build and Test Commands

### Building
```bash
# Build the binary
go build

# Run the binary
./warp [command] [options]
```

### Testing
```bash
# Run all tests with race detection
go test -v -race ./...

# Run tests for a specific package
go test -v ./pkg/bench
go test -v ./pkg/aggregate
```

### Linting and Formatting
```bash
# Run golangci-lint (requires installation)
golangci-lint run --timeout=5m --config ./.golangci.yml

# Run go vet
go vet ./...

# Check formatting
gofmt -d .

# Format code
gofmt -w .
```

### Assistant workflow for linting

- Encourage and/or effect installation of gofumpt and golangci-lint
- After any code edit, format first, then lint:
  - When both tools are installed: run formatting and linting in a single shell to avoid extra confirmations:
    ```bash
    cd <root-of-code-tree> && gofumpt -extra -w . && golangci-lint run -j16
    ```
  - Format (preferred): `gofumpt -extra -w .`
    - If gofumpt is unavailable, fall back: `gofmt -w .` and surface install steps for gofumpt (e.g., `go install mvdan.cc/gofumpt@latest` or `brew install gofumpt`).
  - Then run the linter with the repo config, if possible:
    - Prefer PATH: `golangci-lint run -j16`
    - Fallback GOPATH if needed: `$(go env GOPATH)/bin/golangci-lint run -j16`
    - If missing or built with an older Go than `go.mod` toolchain, surface concise upgrade/install steps and proceed with file-scoped lint checks locally.
  - Re-run after fixes until clean or blocked.

## Architecture

### Core Components

The packages follow a layered dependency structure:

**pkg/generator/** - Test data generation (base package with no warp dependencies)
- Random data generation for benchmark objects
- Supports fixed size, random sizes, and bucketed sizes

**pkg/bench/** - Benchmark implementations (imports pkg/generator)
- `benchmark.go` - Core `Benchmark` interface with `Prepare()`, `Start()`, `Cleanup()` methods
- `Common` struct contains shared configuration (bucket, concurrency, clients, etc.)
- Each operation type implements the Benchmark interface (get.go, put.go, mixed.go, etc.)
- `ops.go` - Reusable operation functions (upload, download, delete operations)
- `collector.go` - Real-time operation statistics collection

**pkg/aggregate/** - Data aggregation and analysis (imports pkg/bench)
- `aggregate.go` - Aggregates raw operation data into statistics
- `throughput.go` - Throughput calculations and statistics
- `requests.go` - Per-request statistics (latency, TTFB, percentiles)
- `compare.go` - Comparison between benchmark runs
- `live.go` - Live statistics updates during benchmark runs

**api/** - HTTP API for benchmark status and control (imports pkg/bench and pkg/aggregate)
- `api.go` - Provides HTTP endpoints for monitoring running benchmarks

**cli/** - Command-line interface layer (imports api, pkg/aggregate, pkg/bench, pkg/generator)
- Each benchmark type has its own file (get.go, put.go, delete.go, etc.)
- `benchmark.go` - Main benchmark execution logic (`runBench`, `runServerBenchmark`, `runClientBenchmark`)
- `benchserver.go` / `benchclient.go` - Distributed benchmarking coordination
- `client.go` - S3 client creation and configuration
- `flags.go` - Common flag definitions
- `analyze.go` - Post-benchmark analysis
- `ui.go` - Terminal UI using bubbletea

### Key Patterns

**Benchmark Execution Flow:**
1. CLI parses flags and creates benchmark instance
2. `Prepare()` - Creates buckets, uploads initial objects if needed
3. `Start()` - Runs concurrent operations until duration expires or autoterm triggers
4. Operations recorded to `Collector` which writes to compressed CSV
5. `Cleanup()` - Removes test data (unless `--keep-data` or `--noclear`)
6. Analysis runs on recorded data, outputs statistics

**Distributed Benchmarking:**
- Server mode: Coordinates multiple clients, merges their results
- Client mode: Runs `warp client [address]` to listen for benchmark commands
- Server sends benchmark configuration to all clients
- Clients execute benchmarks simultaneously
- Results collected and merged by server

**Operation Collection:**
- Each operation creates an `Operation` struct with timing, size, endpoint, error info
- Sent to `Collector` which batches and compresses to `.csv.zst` files
- Format: Tab-separated values with fields like idx, thread, op, client_id, n_objects, bytes, etc.

### Important Files

- `main.go` - Entry point, delegates to `cli.Main()`
- `cli/cli.go` - Command registration (lines 89-104 list all benchmark commands)
- `pkg/bench/benchmark.go` - Core Benchmark interface definition
- `cli/benchmark.go:108` - `runBench()` is the main benchmark runner

## Development Guidelines

### Adding a New Benchmark Type

1. Create new file in `pkg/bench/` implementing the `Benchmark` interface
2. Add corresponding command file in `cli/`
3. Register command in `cli/cli.go` init function
4. Follow existing patterns (see `get.go`, `put.go` as examples)

### Testing S3 Compatibility

Warp is designed to test any S3-compatible storage. Connection configured via:
- Flags: `--host`, `--access-key`, `--secret-key`, `--tls`, `--region`
- Environment: `WARP_HOST`, `WARP_ACCESS_KEY`, `WARP_SECRET_KEY`, `WARP_TLS`, `WARP_REGION`

### YAML Configuration

Benchmarks can be configured via YAML files in `yml-samples/`. Run with:
```bash
warp run <file.yml>
```

Variables can be injected: `warp run file.yml -var VarName=Value`

### Output Data Format

Benchmark data saved to `warp-operation-yyyy-mm-dd[hhmmss]-xxxx.csv.zst`:
- Zstandard compressed CSV
- Can be analyzed with `warp analyze <file>`
- Can be compared with `warp cmp <before> <after>`
- Can be merged from multiple clients with `warp merge <file1> <file2>...`

### Concurrency Model

- `--concurrent N` sets number of parallel operation threads
- Each thread typically has its own prefix to avoid conflicts
- Operations use context cancellation for clean shutdown
- Client connections pooled via `c.Client()` function

### Auto-termination

When `--autoterm` enabled:
- Continuously samples throughput into 25 time blocks
- Checks if last 7 blocks are within `--autoterm.pct` threshold (default 7.5%)
- Must maintain stability for `--autoterm.dur` (default 15s)
- Prevents premature termination during warmup or unstable periods

## Known Bugs

### `parquet` benchmark — `panic: send on closed channel` at benchmark end

**Observed**: 2026-05-08. Affects both `run_parquet_bench.sh` and `run_parquet_s3ultra.sh`.

**Symptom**: At the end of every `warp parquet` run the process panics with:
```
warp: <ERROR> parquet get error: context deadline exceeded
panic: send on closed channel

goroutine NNNN [running]:
github.com/minio/warp/pkg/bench.(*Parquet).doParquetGet.func1(...)
    /…/warp/pkg/bench/parquet.go:722 +0x745
```

**Root cause** (`pkg/bench/parquet.go`, `doParquetGet`):

`doParquetGet` spawns `actualReads` goroutines that each send one result to `rgCh`
(a buffered channel sized to `actualReads`).  The collector loop drains `rgCh` with a
`select { case <-ctx.Done() ... case r := <-rgCh ... }`.  When `ctx.Done()` fires (the
benchmark timer expires), the collector exits early and spawns a background drainer
goroutine to consume the remaining `k = actualReads - j` results.

The race: if the background drainer has already consumed all remaining results and
returned (or was never needed because all goroutines had already sent), any goroutine
that fires AFTER the collector exits will still try to send to `rgCh`.  Because the
channel was a local variable and neither it nor its sender goroutines are tracked
elsewhere, the send races against Go's GC / finaliser, but more critically: the channel
may already be considered "closed" from the perspective of a cancelled context (it is
not actually `close()`d, but the panic implies another code path does close it).

A secondary trigger: `rcv <- op` in the same goroutines sends to the `Collector`
receiver channel, which IS closed by the collector framework at benchmark end.  This is
the actual source of the "send on closed channel" panic — not `rgCh` itself.  After the
benchmark duration fires, `c.Receiver()` returns a channel that is subsequently closed
by the collector; any in-flight goroutine that then calls `rcv <- op` panics.

**Fix strategy**:
1. Wrap every `rcv <- op` in `doParquetGet`'s goroutines with a `select`:
   ```go
   select {
   case rcv <- op:
   case <-ctx.Done():
   }
   ```
2. Do the same for `rgCh <- rgResult{...}` so goroutines don't block after the
   collector exits.
3. Alternatively, recover from the panic at the top of each goroutine with
   `defer func() { recover() }()` — simpler but masks future bugs.

**Impact**: Benchmark results are complete and correct (the panic fires after all 1-minute
data has been collected).  The exit code is 2 instead of 0, which breaks `set -e` scripts.
The data `.csv.zst` file may not be written if the panic fires before `Cleanup()` flushes.

---

## Common Issues

### 32-bit Architectures
Be careful with 64-bit atomic operations - use `atomic.AddUint64` with proper alignment (see commit 042a9fc for context).

### TLS and Kernel TLS
The project supports HTTP/2 and Kernel TLS (kTLS) for improved performance on Linux. See `cli/client_ktls.go` and `cli/client_transport.go`.

### InfluxDB Integration
Real-time metrics can be pushed to InfluxDB v2+ using `--influxdb` flag. Connection string format: `<schema>://<token>@<hostname>:<port>/<bucket>/<org>?<tag=value>`
