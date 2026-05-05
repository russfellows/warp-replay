/*
 * Warp (C) 2019-2025 MinIO, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package cli

import (
	"context"
	"crypto/tls"
	"math"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/minio/cli"
	"golang.org/x/net/http2"
)

var netDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 10 * time.Second,
}

// makeDialer returns a Dialer optionally bound to localIP.
func makeDialer(localIP string) *net.Dialer {
	d := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
	}
	if localIP != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}
	return d
}

type transportOption func(transport *http.Transport)

// withLocalAddr returns a transportOption that binds outbound TCP connections
// to localIP, ensuring they egress via the NIC that owns that address.
func withLocalAddr(localIP string) transportOption {
	return func(transport *http.Transport) {
		if localIP == "" {
			return
		}
		transport.DialContext = makeDialer(localIP).DialContext
	}
}

func withTLSConfig(tlsConfig *tls.Config) transportOption {
	return func(transport *http.Transport) {
		transport.TLSClientConfig = tlsConfig
	}
}

func withDialTLSContext(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) transportOption {
	return func(transport *http.Transport) {
		transport.DialTLSContext = dialer
	}
}

// h2cPool is a round-robin pool of independent http2.Transport instances.
// Each transport is pinned to exactly one TCP connection (MaxConnsPerHost=1),
// so N transports give N parallel h2c sockets — matching the parallelism of
// HTTP/1.1 while still benefiting from h2 frame framing and header compression.
type h2cPool struct {
	pool    []*http2.Transport
	counter atomic.Uint64
}

func (p *h2cPool) RoundTrip(req *http.Request) (*http.Response, error) {
	n := p.counter.Add(1)
	t := p.pool[n%uint64(len(p.pool))]
	return t.RoundTrip(req)
}

// newH2CTransport returns an http.RoundTripper configured for h2c (HTTP/2
// cleartext, no TLS). Unlike http.Transport with ForceAttemptHTTP2, this
// bypasses TLS ALPN negotiation and speaks HTTP/2 frames directly over plain
// TCP — exactly what s3-ultra's hyper-util AutoBuilder expects.
//
// When --h2c-conns > 1 (or auto-calculated from --concurrent), a pool of
// independent h2c connections is used with round-robin dispatch. This gives
// true socket-level parallelism: M connections × S streams each ≈ --concurrent.
//
// --h2c-conns 0 = auto: ceil(concurrent / 32) connections
// --h2c-conns 1 = single connection (original behaviour, all streams share one TCP conn)
// --h2c-conns N = exactly N parallel h2c TCP connections
func newH2CTransport(ctx *cli.Context, localIP string) http.RoundTripper {
	explicitConns := ctx.Int("h2c-conns")
	numConns := explicitConns
	if numConns <= 0 {
		// auto: one connection per 32 concurrent streams
		concurrent := ctx.Int("concurrent")
		if concurrent <= 0 {
			concurrent = 32
		}
		numConns = int(math.Ceil(float64(concurrent) / 32.0))
		if numConns < 1 {
			numConns = 1
		}
		// Auto-fallback: h2c only wins when there are enough concurrent streams
		// to justify multiple TCP connections. Benchmarks show HTTP/1.1 is faster
		// below c=64 (where h2c gets 2 connections). At c≥64, h2c with ceil(c/32)
		// connections consistently beats HTTP/1.1 by 6-10%.
		// Override with --h2c-conns N (N≥1) to force h2c at any concurrency.
		if concurrent < 64 {
			return newClientTransport(ctx, withLocalAddr(localIP))
		}
	}

	// Window size for the h2c receive stream (affects GET throughput for large objects).
	// Default: 4 MiB (64× the HTTP/2 spec minimum of 64 KiB) — eliminates flow-control
	// stalls for objects up to 4 MiB and greatly reduces them beyond that.
	windowMiB := ctx.Int("h2c-window-mib")
	if windowMiB <= 0 {
		windowMiB = 4
	}
	initWindow := uint32(windowMiB) * 1024 * 1024

	makeOne := func() *http2.Transport {
		dialer := makeDialer(localIP)

		// We route through ConfigureTransports so that http.HTTP2Config fields
		// (including MaxReceiveBufferPerStream) are properly wired into the h2
		// transport's internal config. Direct http2.Transport construction has no
		// public field for per-stream window size.
		t1 := &http.Transport{
			DialContext: dialer.DialContext,
			HTTP2: &http.HTTP2Config{
				// Per-stream receive window: controls how much data the server
				// can push before waiting for WINDOW_UPDATE (critical for GET
				// throughput on objects larger than the default 64 KiB window).
				MaxReceiveBufferPerStream: int(initWindow),
				// Connection-level window: set to 4× stream window so multiple
				// concurrent streams don't contend on the same connection budget.
				MaxReceiveBufferPerConnection: int(initWindow) * 4,
			},
		}
		t, err := http2.ConfigureTransports(t1)
		if err != nil {
			// Fallback: shouldn't happen with a fresh transport
			t = &http2.Transport{}
		}

		// Override for h2c: speak HTTP/2 frames over plain TCP (no TLS ALPN).
		t.AllowHTTP = true
		t.DialTLSContext = func(pctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialer.DialContext(pctx, network, addr)
		}
		t.ReadIdleTimeout = 30 * time.Second
		t.PingTimeout = 15 * time.Second
		return t
	}

	if numConns == 1 {
		return makeOne()
	}

	pool := make([]*http2.Transport, numConns)
	for i := range pool {
		pool[i] = makeOne()
	}
	return &h2cPool{pool: pool}
}

func newClientTransport(ctx *cli.Context, options ...transportOption) http.RoundTripper {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           netDialer.DialContext,
		MaxIdleConnsPerHost:   ctx.Int("concurrent"),
		WriteBufferSize:       ctx.Int("sndbuf"), // Configure beyond 4KiB default buffer size.
		ReadBufferSize:        ctx.Int("rcvbuf"), // Configure beyond 4KiB default buffer size.
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		// Set this value so that the underlying transport round-tripper
		// doesn't try to auto decode the body of objects with
		// content-encoding set to `gzip`.
		//
		// Refer:
		//    https://golang.org/src/net/http/transport.go?h=roundTrip#L1843
		DisableCompression: true,
		DisableKeepAlives:  ctx.Bool("disable-http-keepalive"),
		// Because we create a custom TLSClientConfig, we have to opt-in to HTTP/2.
		// See https://github.com/golang/go/issues/14275
		ForceAttemptHTTP2: ctx.Bool("http2"),
	}

	for _, option := range options {
		option(tr)
	}

	return tr
}
