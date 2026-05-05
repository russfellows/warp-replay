# Warp h2c Transport

The `--h2c` flag enables **HTTP/2 cleartext** (h2c, prior-knowledge upgrade) on every
warp benchmark command. This lets warp speak HTTP/2 frames directly over plain TCP —
bypassing TLS entirely — which is the protocol path used by servers like
[s3-ultra](https://github.com/russfellows/s3-ultra) that implement h2c natively.

---

## Background: h2c vs. HTTPS/2 vs. HTTP/1.1

| Mode | Protocol | TLS | When to use |
|------|----------|-----|-------------|
| default | HTTP/1.1 | No | General benchmarking; MaxIdleConnsPerHost controls parallelism |
| `--tls` | HTTP/1.1 + TLS, upgrades to h2 via ALPN if server supports it | Yes | Production TLS endpoints |
| `--h2c` | HTTP/2 cleartext (prior knowledge) | **No** | Servers that speak h2c natively; no TLS overhead |

HTTP/2 over TLS (`--tls` with a server that supports h2 via ALPN) is transparent and
handled automatically. `--h2c` is the explicit opt-in for *cleartext* HTTP/2, where the
client sends an HTTP/2 client preface immediately without any upgrade handshake.

---

## Quick start

```bash
# All benchmark commands work with --h2c
warp get --host localhost:9000 --access-key minioadmin --secret-key minioadmin \
  --h2c --concurrent 64 --duration 60s

warp put --host localhost:9000 --access-key minioadmin --secret-key minioadmin \
  --h2c --concurrent 64 --obj.size 4MiB --duration 60s

warp parquet --host localhost:9000 --access-key minioadmin --secret-key minioadmin \
  --h2c --concurrent 64 --objects 100 --obj.size 128MiB \
  --row-groups 10 --rg-size 8MiB --footer-size 128KiB --rg-reads 2 \
  --duration 2m
```

---

## Flags

### `--h2c`

Enables HTTP/2 cleartext transport. The client sends an HTTP/2 client preface
immediately (prior-knowledge mode — no Upgrade header, no ALPN negotiation).

- Overrides `--tls` and `--ktls` — setting `--h2c` together with `--tls` is safe;
  `--h2c` wins and TLS is not used.
- The server **must** support h2c prior-knowledge. If the server speaks HTTP/1.1
  only, connections will fail immediately.

### `--h2c-conns N`

Number of parallel TCP connections in the h2c pool.

| Value | Behaviour |
|-------|-----------|
| `0` (default) | **Auto**: falls back to HTTP/1.1 when `--concurrent < 64`; uses `ceil(concurrent / 32)` h2c connections when `--concurrent ≥ 64` |
| `1` | Single h2c connection; all streams multiplexed over one TCP socket |
| `N ≥ 2` | Pool of N independent h2c TCP connections with round-robin dispatch |

**Why multiple connections?**
HTTP/2 multiplexes many streams over one TCP connection, but a single TCP socket is
still limited by its congestion window and kernel buffer. For high-throughput
benchmarks (`--concurrent ≥ 64`), splitting across several TCP sockets gives
socket-level parallelism comparable to HTTP/1.1 while retaining h2 framing overhead
reduction.

**Forcing h2c at any concurrency:**
```bash
# Force h2c even at low concurrency (e.g. correctness testing against s3-ultra)
warp get --host localhost:9000 --h2c --h2c-conns 1 --concurrent 4
```

**Auto behaviour summary:**

| `--concurrent` | `--h2c-conns 0` result |
|----------------|------------------------|
| < 64 | HTTP/1.1 (h2c auto-disabled; benchmarks show no gain below this threshold) |
| 64 | 2 h2c connections |
| 96 | 3 h2c connections |
| 128 | 4 h2c connections |
| 256 | 8 h2c connections |

### `--h2c-window-mib N`

HTTP/2 stream receive window size in MiB (applies to both per-stream and
connection-level windows). Default: **4 MiB**.

The HTTP/2 spec default (64 KiB) causes severe flow-control stalls for objects
larger than 64 KiB: the server sends 64 KiB, then waits for a `WINDOW_UPDATE`
before sending more. This serialises what should be a streaming transfer.

**Rule of thumb: set `--h2c-window-mib` to ≥ 2× your largest object size.**

| Object size | Recommended `--h2c-window-mib` |
|-------------|-------------------------------|
| ≤ 4 MiB | 4 (default) |
| 8 MiB | 16 |
| 32 MiB | 64 |
| 128 MiB | 256 |
| ≥ 256 MiB | 512 |

Connection-level window is automatically set to 4× the stream window, so multiple
concurrent streams do not contend for the same connection budget.

```bash
# 128 MiB objects → 256 MiB window
warp parquet --host localhost:9000 --h2c --h2c-window-mib 256 \
  --obj.size 128MiB --concurrent 64
```

---

## Implementation notes

### Transport pool (`h2cPool`)

When `--h2c-conns > 1`, warp creates a pool of independent `http2.Transport`
instances, each capped at one TCP connection (`MaxConnsPerHost` is not exposed on
`http2.Transport`, so isolation is achieved by creating separate transports). Requests
are dispatched round-robin across the pool via an atomic counter — no locking needed.

### Window size wiring

Go's `http2.Transport` does not expose a public field for per-stream receive window
size. The only supported path is:

1. Create an `http.Transport` with an `HTTP2Config` struct specifying
   `MaxReceiveBufferPerStream` and `MaxReceiveBufferPerConnection`.
2. Call `http2.ConfigureTransports(t1)` to get an `*http2.Transport` with those
   settings wired internally.
3. Override `AllowHTTP = true` and set `DialTLSContext` to a plain TCP dialer for h2c.

### TLS override

`getClient()` checks `!ctx.Bool("h2c")` before applying `Secure: true`, ensuring the
minio client never attempts TLS on an h2c connection regardless of the `--tls` flag.

---

## Testing against s3-ultra

s3-ultra uses [hyper-util](https://docs.rs/hyper-util) with the `AutoBuilder` which
automatically detects and handles both HTTP/1.1 and h2c connections. No special
server configuration is needed — just start s3-ultra and use `--h2c` on warp.

```bash
# Start s3-ultra
./s3-ultra serve --port 9000 --access-key minioadmin --secret-key minioadmin

# Benchmark GET with h2c, auto connection count, 64 concurrent workers
./warp get --host localhost:9000 --access-key minioadmin --secret-key minioadmin \
  --h2c --concurrent 64 --obj.size 4MiB --duration 60s

# Compare: same run without h2c (HTTP/1.1)
./warp get --host localhost:9000 --access-key minioadmin --secret-key minioadmin \
  --concurrent 64 --obj.size 4MiB --duration 60s
```

Use `warp cmp` or [polarWarp](https://github.com/russfellows/polarWarp) to compare
the two result files and measure the h2c vs. HTTP/1.1 throughput delta.
