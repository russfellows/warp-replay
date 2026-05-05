# Changelog — warp-replay

warp-replay is a fork of [MinIO warp](https://github.com/minio/warp) maintained at
[github.com/russfellows/warp-replay](https://github.com/russfellows/warp-replay).

Version numbers follow the scheme **`v<upstream-base>-replay.<N>`** — e.g.
`v1.4.1-replay.2` means the fork is based on upstream warp `v1.4.1` and this is
the second fork-specific release on that base.

---

## v1.4.1-replay.2 — 2026-05-05

**New feature: Parquet benchmark (`warp parquet`)**

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
|---------------------|--------------------|
| v1.4.1-replay.2 | v1.4.1 |
| v1.4.1-replay.1 | v1.4.1 |
| v1.4.0-replay.1 | v1.4.0 |
