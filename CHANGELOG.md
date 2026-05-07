# Changelog — warp-replay

warp-replay is a fork of [MinIO warp](https://github.com/minio/warp) maintained at
[github.com/russfellows/warp-replay](https://github.com/russfellows/warp-replay).

Version numbers follow the scheme **`v<upstream-base>-replay.<N>`** — e.g.
`v1.4.1-replay.2` means the fork is based on upstream warp `v1.4.1` and this is
the second fork-specific release on that base.

---

## v1.4.1-replay.3 — 2026-05-07

**Parquet benchmark: per-request op-log accuracy, op-log tracing for prepare phase,
random-without-replacement RG selection, `--rg-sequential` flag, docs and scripts**

### Fix: each row-group GET is now a separate op-log entry

Previously `doParquetGet` issued `--rg-reads` byte-range GETs in parallel but
rolled their bytes and timing into a single `Operation` record — e.g. four
~8.3 MiB GETs appeared as one 33.3 MiB entry. The op-log goal is to exactly
reflect every HTTP request sent on the wire; coalescing violated that.

Now each goroutine constructs and sends its own `Operation` to the collector
(with individual start/end timestamps, TTFB, and byte count) before the read
loop completes. The outer wrapper op has been removed entirely.

**Verified** (64 × 1 GiB DLRM files, `--rg-reads 4`, `--concurrent 20`, 60 s):
- 308,124 individual `GET` entries — 100% for exactly one row group (~8.3 MiB)
- Peak 80 concurrent in-flight GETs (20 threads × 4 goroutines each)
- Modal steady-state concurrency: ~52

### Fix: row-group selection is now random without replacement

The previous code drew each of the `--rg-reads` indices independently with
`rng.Intn(len(groups))` — the same row group could be selected twice in one
operation, giving inflated throughput on servers with object-level caching.

Replaced with a partial Fisher-Yates shuffle: `--rg-reads` distinct indices are
selected in O(rg-reads) time with no allocations beyond the index slice.

### New flag: `--rg-sequential`

Picks `--rg-reads` **consecutive** row groups starting at a random offset instead
of random-without-replacement. Models the DLRM and similar file-major sequential
access patterns used during AI/ML training epochs.

### New: prepare-phase ops recorded in op-log

When `--list-existing` is used, the prepare phase previously issued a bucket LIST
and per-file footer byte-range GETs with no trace visibility. These are now
recorded as distinct op types:

| Op type | Description |
|---------|-------------|
| `LIST` | Initial bucket listing — 1 per run |
| `GET-FOOTER` | Per-file footer byte-range GET — N per run (2N when `--footer-size` triggers a retry) |
| `GET` | Benchmark loop row-group byte-range GETs |

The retry case (footer too small for first attempt) records **both** the failed
attempt and the successful retry as separate `GET-FOOTER` ops, accurately
reflecting the prepare-phase I/O cost.

### Docs: README_PARQUET.md fully rewritten

- Thread/goroutine/concurrency flow diagram explaining 20 threads → 80 in-flight GETs
- Verified concurrency numbers from real DLRM runs
- Op-log section: op types, awk inspection snippets
- `--rg-sequential` flag documented
- Corrected benchmark loop description (footer cached at startup, not re-fetched)

### New: `scripts/` directory

`scripts/run_parquet_bench.sh` — convenience wrapper for running the Parquet
benchmark against s3-ultra with `--list-existing --keep-data --full`.
Supports optional `--rg-sequential` argument.

### Removed: `docs/issue-streaming-full-writer.md`

Design proposal for the streaming zst writer, which has been fully implemented
since v1.4.1-replay.1. The implemented design is documented in
`docs/Warp-streaming-log-Design.md`.

---

## v1.4.1-replay.2 — 2026-05-05

**New features: Parquet benchmark (`warp parquet`) and h2c transport (`--h2c`)**

### New feature: h2c transport (`--h2c`)

Adds HTTP/2 cleartext (h2c, prior-knowledge) transport support to every benchmark
command. This is specifically useful for servers like s3-ultra that speak h2c
natively — warp now exercises the same protocol path as production AI/ML clients
without requiring TLS termination overhead.

**New flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--h2c` | false | Use HTTP/2 cleartext (no TLS). Implies `--insecure`, overrides `--tls`/`--ktls`. |
| `--h2c-conns` | 0 (auto) | Parallel h2c TCP connections. `0` = auto: falls back to HTTP/1.1 below 64 concurrent, uses `ceil(concurrent/32)` connections at ≥64. Set `≥1` to force h2c at any concurrency. |
| `--h2c-window-mib` | 0 (→ 4 MiB) | HTTP/2 stream receive window in MiB. The spec default (64 KiB) causes flow-control stalls for objects larger than 64 KiB. Rule of thumb: set to ≥ 2× largest object size. |

**Implementation highlights:**
- `h2cPool`: round-robin pool of independent `http2.Transport` instances, one TCP
  socket each. Gives socket-level parallelism comparable to HTTP/1.1 (no head-of-line
  blocking across unrelated operations).
- Window sizes wired via `http.HTTP2Config` + `http2.ConfigureTransports` — the only
  Go stdlib path that exposes per-stream receive buffer control.
- `--h2c` silently overrides `Secure: true` so users cannot accidentally request both
  TLS and h2c simultaneously.

---

### New feature: Parquet benchmark (`warp parquet`)**

This release adds the `parquet` benchmark command — the first benchmark in any warp
variant to model the AI/ML Parquet I/O access pattern end-to-end. Parquet is the
dominant columnar format for AI/ML training datasets and checkpoints; query engines
(Spark, DuckDB, Trino, PyArrow, etc.) read it with a three-phase access pattern that
is fundamentally different from a simple GET:

1. **Footer range GET** — read the last N bytes to retrieve the Thrift-encoded
   `FileMetaData` footer.
2. **Footer parse** — decode the Thrift CompactProtocol footer to extract row-group
   offsets and sizes.
3. **Row-group range GETs** — issue one byte-range GET per row group (parallelised).

### Why this matters

Object stores that implement Parquet-aware caching — such as
[s3-ultra](https://github.com/russfellows/s3-ultra) — store the Parquet footer
separately from the object body and serve it from a fast metadata path. A naive
benchmark that only measures full-object throughput cannot stress-test or validate
this optimisation. `warp parquet` exercises the exact read path these stores are
designed to accelerate.

### What was implemented

| File | Description |
|------|-------------|
| `pkg/bench/parquet_footer.go` | Hand-rolled Thrift CompactProtocol encoder and decoder — zero external dependencies. Ported from [gcsfuse-bench](https://github.com/russfellows/gcsfuse-bench) with Apache 2.0 attribution. Provides `BuildParquetObject` and `ParseParquetFooter`. |
| `pkg/bench/parquet.go` | `Parquet` benchmark struct implementing the `Benchmark` interface: `Prepare` (upload objects), `Start` (three-phase GET loop), `Cleanup`. |
| `cli/parquet.go` | `warp parquet` command, flags, help text, and syntax validation. |
| `cli/cli.go` | Registered `parquetCmd` in the benchmark command list. |

### New flags (`warp parquet`)

| Flag | Default | Description |
|------|---------|-------------|
| `--objects` | 100 | Objects to upload in the prepare phase |
| `--obj.size` | 128MiB | Size of each Parquet object |
| `--row-groups` | 10 | Number of row groups per object |
| `--rg-size` | 8MiB | Byte size of each row group |
| `--footer-size` | 128KiB | Bytes to read in the footer range GET |
| `--rg-reads` | 2 | Parallel row-group GETs per benchmark op |
| `--list-existing` | false | Skip upload; use objects already in the bucket |

All standard benchmark flags (`--concurrent`, `--duration`, `--host`, `--bucket`,
`--prefix`, `--full`, `--benchdata`, etc.) are also available.

### Validated results

Smoke-tested against s3-ultra v0.2.0 running locally:

- 5 × 4 MiB objects, 4 row groups, 512 KiB per group, 128 KiB footer, 2 concurrent workers
- 32,354 operations in 12 s — **~2.7 GB/s, ~2,420 obj/s**, p99 latency 1.9 ms
- Zero errors; TTFB effectively 0 (all served from s3-ultra's in-memory footer cache)

### Documentation

See [docs/README_PARQUET.md](docs/README_PARQUET.md) for full setup, flag reference,
testing methodology, and worked examples.

---

## v1.4.1-replay.1 — 2026-04-18 *(unreleased tag)*

**Base bumped to upstream warp v1.4.1**

Merged upstream warp `v1.4.1` into the fork. No fork-specific functional changes;
this release captures the rebase and the lognormal size distribution addition on
the new upstream base.

### Feature: lognormal object size distribution (`--obj.rand-logn`)

Added a second random-size distribution alongside the existing log₂ distribution
(`--obj.randsize` / `--obj.rand-log2`).

| Flag | Distribution | `--obj.size` means |
|------|--------------|--------------------|
| `--obj.randsize` / `--obj.rand-log2` | log₂ | target average |
| `--obj.rand-logn` | lognormal | target median |

`--obj.randsize.sigma` (default `1.0`) controls the log-space spread for
`--obj.rand-logn`.

---

## v1.4.0-replay.1 — 2026-04-07

**First warp-replay release on upstream v1.4.0 base**

### Feature: Workload replay (`warp replay`)

Replays any prior warp `.csv.zst` trace file against a new S3 target. Supports
optional YAML host-remapping config (`--config`). The
[s3dlio](https://github.com/russfellows/s3dlio) library emits warp-format traces,
making any s3dlio workload replayable.

Key flags: `--file`, `--bucket`, `--host`, `--config`, `--log-warp-ops`.

### Feature: Streaming per-transaction log (`--full`)

Adds `--full` to every benchmark command, writing a live zstd-compressed
per-operation CSV log during the run. Unlike the upstream in-memory `--full` PR,
this implementation streams directly to disk — RAM overhead is constant at a few
MB regardless of run duration or operation count.

See [docs/Warp-streaming-log-Design.md](docs/Warp-streaming-log-Design.md) for
design notes.

### Feature: Makefile + binary naming

Added `Makefile` with `build`, `install`, `test`, `clean` targets. The output
binary is named `warp` (not `warp-replay`) so it is a drop-in replacement for
upstream warp on the PATH.

---

## Upstream base versions

| warp-replay version | Upstream warp base |
|---------------------|-----------------|
| v1.4.1-replay.3 | v1.4.1 |
| v1.4.1-replay.1 | v1.4.1 |
| v1.4.0-replay.1 | v1.4.0 |
