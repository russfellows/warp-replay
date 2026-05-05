# Warp Parquet Benchmark

> **Status**: Feature-complete and validated against s3-ultra v0.2.0.

The `warp parquet` command benchmarks the **AI/ML Parquet I/O access pattern** —
the three-phase read sequence used by every modern query engine (Spark, DuckDB,
Trino, PyArrow, Arrow Flight, …) when scanning Parquet objects stored in object
storage.

---

## Background: Why Parquet needs its own benchmark

Standard S3 benchmarks measure raw GET throughput with full-object reads. Parquet
access is structurally different:

```
Object layout
─────────────
  ┌──────────────────────────────────────────────────┐
  │  PAR1  (4 bytes magic)                           │
  │  Row Group 0  (rgSize bytes of columnar data)    │
  │  Row Group 1                                     │
  │  …                                               │
  │  Row Group N-1                                   │
  │  [optional padding]                              │
  │  FileMetaData (Thrift CompactProtocol footer)    │
  │  footer_length  (4-byte LE uint32)               │
  │  PAR1  (4 bytes magic)                           │
  └──────────────────────────────────────────────────┘
```

A query engine that needs columns from row group 3 does:

1. **Footer range GET** — `GET` last N bytes (typically 16 KiB–512 KiB) to read
   the `FileMetaData` Thrift footer.
2. **Footer parse** — decode the Thrift CompactProtocol structure to find the byte
   offset and length of row group 3.
3. **Row-group range GET** — `GET bytes=<offset>-<offset+length-1>` to retrieve
   only the columns needed.

This three-phase pattern is the reason that Parquet-aware object stores (such as
[s3-ultra](https://github.com/russfellows/s3-ultra)) store the footer separately
and can serve it from a fast metadata path — avoiding a round-trip to the object
body entirely.

`warp parquet` exercises exactly this access pattern, making it possible to:

- Measure how fast a target serves the footer vs. full-object GET.
- Validate correctness: the benchmark decodes the Thrift footer on every operation
  and verifies the row-group offsets it receives are structurally valid. A server
  that returns garbage bytes for a range request will fail the parse step.
- Stress-test parallel row-group I/O via concurrent range GETs within each op.

---

## Quick start

```bash
# Build warp (if not already done)
cd /path/to/warp-replay
make

# Basic Parquet benchmark against MinIO or s3-ultra on localhost:9000
./warp parquet \
  --host localhost:9000 \
  --access-key minioadmin \
  --secret-key minioadmin \
  --bucket parquet-bench \
  --objects 50 \
  --obj.size 128MiB \
  --row-groups 10 \
  --rg-size 8MiB \
  --footer-size 128KiB \
  --rg-reads 2 \
  --concurrent 8 \
  --duration 60s
```

---

## Flags

### Parquet-specific flags

| Flag | Default | Description |
|------|---------|-------------|
| `--objects` | 100 | Number of Parquet objects to upload during the prepare phase. |
| `--obj.size` | 128MiB | Total size of each Parquet object. Supports human-friendly sizes: `64MiB`, `1GiB`, etc. |
| `--row-groups` | 10 | Number of row groups to embed in each object. Each row group gets an accurate Thrift-encoded offset in the footer. |
| `--rg-size` | 8MiB | Byte size of each row group. The actual object layout is: `4B PAR1 + rgCount×rgSize + footer`. |
| `--footer-size` | 128KiB | How many bytes to fetch in the footer read phase (`GET bytes=<objSize-footerSize>-<objSize-1>`). Must be ≥ the actual encoded footer. |
| `--rg-reads` | 2 | Number of **parallel** row-group byte-range GETs per benchmark operation. Values from 1 (sequential) to `--row-groups` (all groups) are valid. |
| `--list-existing` | false | Skip the upload phase. Use objects already present in the bucket as the GET corpus. The benchmark will list the bucket and use whatever it finds. |

### Standard benchmark flags (inherited)

All the usual warp flags are available:

| Flag | Description |
|------|-------------|
| `--host` | S3 endpoint(s), comma-separated or expandable (e.g. `node{1..8}:9000`) |
| `--access-key` / `--secret-key` | S3 credentials |
| `--bucket` | Bucket name (created automatically if it does not exist) |
| `--prefix` | Object key prefix (default: random per-run prefix to avoid collisions) |
| `--concurrent` | Number of concurrent benchmark goroutines (default: 20) |
| `--duration` | Benchmark duration (default: 5m) |
| `--tls` | Use TLS (default: false) |
| `--full` | Write a streaming per-operation `.csv.zst` log to disk |
| `--benchdata` | Output path prefix for result files |
| `--noclear` | Do not delete objects after the benchmark (useful for `--list-existing` follow-on runs) |
| `--autoterm` | Auto-terminate when throughput stabilises |

---

## How the benchmark works

### Prepare phase

For each of the `--objects` objects, warp:

1. Generates a structurally valid Parquet byte stream using the hand-rolled Thrift
   CompactProtocol encoder in `pkg/bench/parquet_footer.go`.
2. The object contains a real `PAR1` magic header, `--row-groups` row groups of
   `--rg-size` bytes each, and a valid Thrift `FileMetaData` footer with accurate
   `row_group.file_offset` values.
3. Uploads the object with content-type `application/x-parquet` using a concurrent
   worker pool.

The in-memory row-group layout (offset, size for every group) is retained in the
benchmark's `objects` slice and used in the benchmark loop.

### Benchmark loop

Each goroutine, on every iteration until `--duration` expires:

1. **Pick a random object** from the prepared corpus.
2. **Footer range GET**: issue `GET bytes=<objSize - footerSize>-<objSize - 1>`.
3. **Parse footer**: call `ParseParquetFooter` on the returned bytes. This decodes
   the Thrift CompactProtocol `FileMetaData` and returns `[]ParquetRowGroup`
   (offset + size for each group). If parsing fails, the operation is recorded as
   an error.
4. **Row-group GETs**: launch `--rg-reads` goroutines, each issuing a separate
   byte-range GET for a randomly-chosen row group. All goroutines run in parallel;
   the operation completes when all have finished.
5. **Record**: total bytes transferred (footer + all row groups), TTFB (from start
   of footer GET to first byte received), and wall-clock latency are recorded.

### Operation type reported

The benchmark reports operations under the `GET` type (byte-range GETs are the
dominant operation). The `--full` trace log records each individual operation with
`first_byte` timing.

---

## Testing against s3-ultra

[s3-ultra](https://github.com/russfellows/s3-ultra) is a Parquet-aware fake S3
server that stores Parquet footers in a separate Fjall keyspace and serves them
from the metadata path — bypassing the object-body store entirely.

### Starting s3-ultra

```bash
# Basic start (stores data in /tmp/s3-ultra-db)
./s3-ultra serve \
  --port 9000 \
  --access-key minioadmin \
  --secret-key minioadmin

# With Parquet footer storage enabled (recommended for parquet benchmark)
./s3-ultra serve \
  --port 9000 \
  --access-key minioadmin \
  --secret-key minioadmin \
  --parquet-footer-bytes 131072   # store up to 128 KiB footer per object
```

### Running the Parquet benchmark

```bash
# Quick smoke test (5 small objects, 15 seconds)
./warp parquet \
  --host localhost:9000 \
  --access-key minioadmin \
  --secret-key minioadmin \
  --bucket parquet-test \
  --objects 5 \
  --obj.size 4MiB \
  --row-groups 4 \
  --rg-size 512KiB \
  --footer-size 128KiB \
  --rg-reads 2 \
  --concurrent 2 \
  --duration 15s

# Full throughput benchmark (100 objects, 128 MiB each, 8 concurrent)
./warp parquet \
  --host localhost:9000 \
  --access-key minioadmin \
  --secret-key minioadmin \
  --bucket parquet-bench \
  --objects 100 \
  --obj.size 128MiB \
  --row-groups 10 \
  --rg-size 8MiB \
  --footer-size 128KiB \
  --rg-reads 2 \
  --concurrent 8 \
  --duration 2m \
  --full  # also write per-operation CSV log

# High-concurrency stress test
./warp parquet \
  --host localhost:9000 \
  --access-key minioadmin \
  --secret-key minioadmin \
  --bucket parquet-stress \
  --objects 200 \
  --obj.size 256MiB \
  --row-groups 16 \
  --rg-size 12MiB \
  --footer-size 256KiB \
  --rg-reads 4 \
  --concurrent 32 \
  --duration 5m
```

### What to look for

| Metric | What it tells you |
|--------|------------------|
| **obj/s** | Operations per second — one op = 1 footer GET + N row-group GETs |
| **MiB/s** | Total bytes transferred (footer bytes + all row-group bytes) |
| **TTFB** | Time from start of footer GET to first footer byte received. Near-zero on s3-ultra means the footer is being served from the fast metadata path. |
| **p99 latency** | Tail latency — important for interactive query workloads |
| **Errors** | Any non-zero error count means the Thrift footer parse failed or a range GET returned bad data |

### Validating correctness

The `ParseParquetFooter` call in step 3 of the benchmark loop is a live correctness
check. It:

- Verifies the PAR1 magic at the start and end of the footer bytes.
- Decodes the Thrift `FileMetaData` structure.
- Returns the row-group offsets and sizes.

If a server returns random bytes for a range request (instead of the real footer),
the parse will fail and the operation is recorded as an error. A successful run
with zero errors means the server is correctly serving the Parquet footer bytes at
the expected byte offsets.

---

## Using existing Parquet objects (`--list-existing`)

If you already have real Parquet files in a bucket (e.g. uploaded by a training
job), you can skip the synthetic upload phase:

```bash
./warp parquet \
  --host s3.example.com \
  --access-key KEY \
  --secret-key SECRET \
  --bucket my-training-data \
  --list-existing \
  --prefix datasets/imagenet/ \
  --footer-size 512KiB \   # real Parquet footers can be large
  --rg-reads 4 \
  --concurrent 16 \
  --duration 5m
```

**Note**: `--footer-size` must be at least as large as the actual footer in your
objects. If the Thrift decode fails, increase `--footer-size`.

---

## Implementation details

### Thrift encoder/decoder (`pkg/bench/parquet_footer.go`)

The encoder and decoder use Thrift CompactProtocol with no external dependencies —
only the Go standard library (`encoding/binary`, `fmt`, `math/rand`). This is
ported from the [gcsfuse-bench](https://github.com/russfellows/gcsfuse-bench)
project with Apache 2.0 attribution.

The encoded `FileMetaData` contains:
- `version` (Parquet format version 2)
- `schema` — two schema elements: a required message type and one optional
  `BYTE_ARRAY` column
- `num_rows` — set to 1 per row group for simplicity
- `row_groups` — one `RowGroup` per group, each with:
  - `columns` — one `ColumnChunk` with accurate `file_offset` and `total_compressed_size`
  - `total_byte_size` — equals `--rg-size`
  - `num_rows` — 1

The decoder (`ParseParquetFooter`) handles delta-encoded field IDs, ZigZag-encoded
i32/i64 values, and compact 1-byte list headers per the Thrift CompactProtocol spec.

### Object layout

```
offset 0                 : PAR1  (4 bytes)
offset 4                 : Row Group 0  (rgSize bytes)
offset 4 + 1×rgSize      : Row Group 1
…
offset 4 + (N-1)×rgSize  : Row Group N-1
offset 4 + N×rgSize      : FileMetaData (Thrift, variable length)
offset 4 + N×rgSize + M  : footer_length  (4-byte LE uint32, value = M)
offset 4 + N×rgSize + M+4: PAR1  (4 bytes)
```

Total object size = `8 + N×rgSize + len(FileMetaData) + 4`
(rounded to nearest byte; the `--obj.size` flag is the target, actual size may
differ slightly due to the fixed overhead).

---

## Compared to other approaches

| Approach | What it tests | Parquet correctness? |
|----------|--------------|----------------------|
| `warp get` | Full-object throughput | No |
| `warp mixed` | Combined PUT/GET/DELETE | No |
| `warp parquet` | Footer range GET + parse + row-group GETs | **Yes** |

The Thrift footer parse in every operation means that `warp parquet` is the only
benchmark approach that can distinguish between:

- A server that returns real Parquet footer bytes (passes parse)
- A server that generates random bytes for range requests (fails parse with `ErrNotParquet`)

This is particularly important when benchmarking servers with Parquet-specific
caching layers (like s3-ultra's `--parquet-footer-bytes` feature).
