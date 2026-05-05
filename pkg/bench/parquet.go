/*
 * Warp (C) 2019-2020 MinIO, Inc.
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

// Package bench — Parquet benchmark.
//
// The Parquet benchmark exercises the full AI/ML Parquet I/O pattern against
// any S3-compatible server:
//
//  1. Prepare: upload N objects that are structurally valid Parquet files (real
//     PAR1 magic, real Thrift CompactProtocol FileMetaData footer, accurate
//     row-group byte offsets).
//
//  2. Benchmark loop (per goroutine):
//     a. Footer read  — byte-range GET of the last --footer-size bytes.
//     b. Footer parse — decode the Thrift FileMetaData to extract real row-group
//        offsets (verifies the server returned the real footer, not synthesised bytes).
//     c. Row-group GETs — --rg-reads parallel byte-range GETs, each hitting one
//        randomly chosen row group at its actual byte offset.
//
// When run against s3-ultra this validates:
//   - That s3-ultra correctly captured the Parquet footer on PUT.
//   - That range GETs of the footer region return real footer bytes (not
//     synthesised random data).
//   - That row-group range GETs work and return the correct byte count.
//   - Full throughput characteristics of the server under Parquet workloads.

package bench

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
)

// parquetEntry records per-object metadata needed for the GET benchmark phase.
// We store it separately from generator.Object because we need the row-group
// layout that was baked into each object at upload time.
type parquetEntry struct {
	Name   string
	Size   int64
	Groups []ParquetRowGroup // row-group offsets/sizes from BuildParquetObject
}

// Parquet benchmarks the Parquet-specific I/O pattern:
//
//   - PUT: upload structurally valid Parquet objects.
//   - GET: footer read + parse + parallel row-group range GETs.
type Parquet struct {
	Common

	// Configuration (set by CLI before Prepare).
	CreateObjects int
	ObjSize       int64  // bytes per object
	RowGroupCount int    // row groups to embed per object
	RowGroupSize  int64  // bytes per row group
	FooterSize    int64  // bytes to fetch for footer read
	RGReads       int    // parallel row-group GETs per benchmark op
	ListExisting  bool   // skip upload; list objects already in the bucket
	ListPrefix    string // prefix filter for --list-existing

	objects []parquetEntry
}

// Prepare uploads Parquet objects (or lists existing ones when --list-existing).
func (p *Parquet) Prepare(ctx context.Context) error {
	if p.ListExisting {
		return p.prepareFromExisting(ctx)
	}
	return p.prepareUpload(ctx)
}

// prepareFromExisting lists objects already in the bucket and uses them as the
// read corpus.  The row-group layout is not known, so row-group GETs fall back
// to a random 1×RGSize range within the object body.
func (p *Parquet) prepareFromExisting(ctx context.Context) error {
	objs, err := p.listExistingObjects(ctx, ListObjectsConfig{
		Bucket:         p.Bucket,
		Prefix:         p.ListPrefix,
		CreateObjects:  p.CreateObjects,
		FilterZeroSize: true,
	})
	if err != nil {
		return err
	}
	p.objects = make([]parquetEntry, len(objs))
	for i, o := range objs {
		p.objects[i] = parquetEntry{Name: o.Name, Size: o.Size}
	}
	return nil
}

// prepareUpload creates the bucket and uploads Parquet objects.
func (p *Parquet) prepareUpload(ctx context.Context) error {
	if err := p.createEmptyBucket(ctx); err != nil {
		return err
	}

	p.UpdateStatus(fmt.Sprintf("Uploading %d Parquet objects (%d row groups × %d bytes each)",
		p.CreateObjects, p.RowGroupCount, p.RowGroupSize))

	var (
		mu       sync.Mutex
		groupErr error
		wg       sync.WaitGroup
	)

	objs := splitObjs(p.CreateObjects, p.Concurrency)
	rcv := p.Collector.Receiver()

	wg.Add(p.Concurrency)
	for i, objSlice := range objs {
		go func(threadIdx int, objSlice []struct{}) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(threadIdx)*6364136223846793005 + 1442695040888963407))

			// Use the generator source only for object naming; data is built here.
			src := p.Source()

			for range objSlice {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if p.rpsLimit(ctx) != nil {
					return
				}

				// Generate a unique object name via the normal source.
				nameSrc := src.Object()
				name := nameSrc.Name

				// Build a structurally valid Parquet object in memory.
				data, groups, err := BuildParquetObject(rng, p.ObjSize, p.RowGroupCount, p.RowGroupSize)
				if err != nil {
					p.Error("parquet build error:", err)
					mu.Lock()
					if groupErr == nil {
						groupErr = err
					}
					mu.Unlock()
					return
				}

				client, cldone := p.Client()
				op := Operation{
					OpType:   http.MethodPut,
					Thread:   uint32(threadIdx),
					Size:     int64(len(data)),
					File:     name,
					ObjPerOp: 1,
					Endpoint: client.EndpointURL().String(),
				}

				opts := p.PutOpts
				opts.ContentType = "application/x-parquet"

				op.Start = time.Now()
				res, putErr := client.PutObject(ctx, p.Bucket, name,
					bytes.NewReader(data), int64(len(data)), opts)
				op.End = time.Now()
				cldone()

				if putErr != nil {
					err := fmt.Errorf("upload error: %w", putErr)
					p.Error(err)
					mu.Lock()
					if groupErr == nil {
						groupErr = err
					}
					mu.Unlock()
					return
				}
				if res.Size != int64(len(data)) {
					err := fmt.Errorf("short upload: want %d, got %d", len(data), res.Size)
					p.Error(err)
					mu.Lock()
					if groupErr == nil {
						groupErr = err
					}
					mu.Unlock()
					return
				}

				rcv <- op

				mu.Lock()
				p.objects = append(p.objects, parquetEntry{
					Name:   name,
					Size:   int64(len(data)),
					Groups: groups,
				})
				p.prepareProgress(float64(len(p.objects)) / float64(p.CreateObjects))
				mu.Unlock()
			}
		}(i, objSlice)
	}
	wg.Wait()
	return groupErr
}

// GetCommon returns the embedded Common parameters.
func (p *Parquet) GetCommon() *Common {
	return &p.Common
}

// Cleanup removes all objects and the bucket after the benchmark.
func (p *Parquet) Cleanup(ctx context.Context) {
	p.deleteAllInBucket(ctx)
}

// ── GET benchmark loop ───────────────────────────────────────────────────────

// Start executes the Parquet GET benchmark.
//
// Each goroutine loops until ctx is cancelled.  One iteration consists of:
//  1. Footer read  — range GET of the last FooterSize bytes.
//  2. Footer parse — Thrift decode to extract real row-group byte offsets.
//  3. Row-group GETs — RGReads parallel range GETs at the row-group offsets
//     obtained from step 2.  When row-group metadata is unavailable (objects
//     listed with --list-existing), a single random range of RowGroupSize bytes
//     is used instead.
//
// The recorded Operation captures total bytes = footer bytes + all row-group bytes.
func (p *Parquet) Start(ctx context.Context, wait chan struct{}) error {
	var wg sync.WaitGroup
	wg.Add(p.Concurrency)

	c := p.Collector
	if p.AutoTermDur > 0 {
		ctx = c.AutoTerm(ctx, "GET", p.AutoTermScale, autoTermCheck, autoTermSamples, p.AutoTermDur)
	}

	// Non-cancellable context for operations in flight when ctx is cancelled;
	// we use ctx directly for all S3 calls so cancellation drains gracefully.
	for i := 0; i < p.Concurrency; i++ {
		go func(threadIdx int) {
			defer wg.Done()

			rng := rand.New(rand.NewSource(int64(threadIdx)*6364136223846793005 + 1))
			rcv := c.Receiver()
			done := ctx.Done()

			<-wait
			for {
				select {
				case <-done:
					return
				default:
				}
				if p.rpsLimit(ctx) != nil {
					return
				}

				entry := p.objects[rng.Intn(len(p.objects))]
				client, cldone := p.Client()

				op := Operation{
					OpType:   http.MethodGet,
					Thread:   uint32(threadIdx),
					File:     entry.Name,
					ObjPerOp: 1,
					Endpoint: client.EndpointURL().String(),
				}
				if p.DiscardOutput {
					op.File = ""
				}

				op.Start = time.Now()
				totalBytes, firstByte, err := p.doParquetGet(ctx, client, rng, entry)
				op.End = time.Now()
				cldone()

				op.Size = totalBytes
				op.FirstByte = firstByte
				if err != nil {
					op.Err = err.Error()
					p.Error("parquet get error:", err)
				}
				rcv <- op
			}
		}(i)
	}

	wg.Wait()
	return nil
}

// doParquetGet performs the three-phase Parquet GET:
//
//  1. Range GET footer (last FooterSize bytes)
//  2. Parse footer → row-group offsets
//  3. RGReads parallel row-group range GETs
//
// Returns (totalBytes, firstByteTime, error).
func (p *Parquet) doParquetGet(
	ctx context.Context,
	client *minio.Client,
	rng *rand.Rand,
	entry parquetEntry,
) (totalBytes int64, firstByte *time.Time, err error) {

	footerSize := p.FooterSize
	if footerSize <= 0 {
		footerSize = 131072 // 128 KiB default
	}

	// ── Phase 1: footer byte-range GET ──────────────────────────────────────
	//
	// Calculate the absolute byte range: [objectSize-footerSize, objectSize-1].
	// We use the stored object size to avoid an extra HEAD round-trip.
	objSize := entry.Size
	footerStart := objSize - footerSize
	if footerStart < 0 {
		footerStart = 0
		footerSize = objSize
	}

	footerOpts := minio.GetObjectOptions{}
	if err2 := footerOpts.SetRange(footerStart, objSize-1); err2 != nil {
		return 0, nil, fmt.Errorf("set footer range: %w", err2)
	}

	footerObj, err2 := client.GetObject(ctx, p.Bucket, entry.Name, footerOpts)
	if err2 != nil {
		return 0, nil, fmt.Errorf("footer GET: %w", err2)
	}

	footerBuf := make([]byte, footerSize)
	var footerRead int
	ttfbRecorded := false
	for footerRead < int(footerSize) {
		nr, rerr := footerObj.Read(footerBuf[footerRead:])
		if !ttfbRecorded && nr > 0 {
			t := time.Now()
			firstByte = &t
			ttfbRecorded = true
		}
		footerRead += nr
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			footerObj.Close()
			return 0, firstByte, fmt.Errorf("footer read: %w", rerr)
		}
		select {
		case <-ctx.Done():
			footerObj.Close()
			return 0, firstByte, ctx.Err()
		default:
		}
	}
	footerObj.Close()
	totalBytes += int64(footerRead)

	// ── Phase 2: parse footer ────────────────────────────────────────────────
	//
	// Decode the Thrift FileMetaData to get real row-group byte offsets.
	// This also validates that the server returned real Parquet footer bytes.
	groups, parseErr := ParseParquetFooter(footerBuf[:footerRead], objSize)
	if parseErr != nil && parseErr != ErrNotParquet {
		// Not-Parquet is a soft error (e.g. --list-existing with non-Parquet
		// objects); other parse errors indicate corrupt footer data.
		return totalBytes, firstByte, fmt.Errorf("ParseParquetFooter(%s): %w", entry.Name, parseErr)
	}

	// Fall back to the row-group layout we embedded at upload time if the
	// parsed footer came up empty (e.g. --list-existing).
	if len(groups) == 0 && len(entry.Groups) > 0 {
		groups = entry.Groups
	}

	// ── Phase 3: parallel row-group GETs ─────────────────────────────────────
	rgReads := p.RGReads
	if rgReads <= 0 {
		rgReads = 1
	}

	type rgResult struct {
		n   int64
		err error
	}
	rgCh := make(chan rgResult, rgReads)

	for j := 0; j < rgReads; j++ {
		var rgStart, rgEnd int64

		if len(groups) > 0 {
			// Pick a random row group from the decoded (or stored) layout.
			rg := groups[rng.Intn(len(groups))]
			rgStart = rg.Offset
			rgEnd = rg.Offset + rg.Size - 1
			if rgEnd >= objSize {
				rgEnd = objSize - 1
			}
		} else {
			// No row-group metadata available; pick a random range of RowGroupSize.
			rgSize := p.RowGroupSize
			if rgSize <= 0 {
				rgSize = 8 * 1024 * 1024 // 8 MiB default
			}
			if rgSize >= objSize {
				rgStart = 0
				rgEnd = objSize - 1
			} else {
				rgStart = rng.Int63n(objSize - rgSize)
				rgEnd = rgStart + rgSize - 1
			}
		}

		go func(start, end int64) {
			opts2 := minio.GetObjectOptions{}
			if serr := opts2.SetRange(start, end); serr != nil {
				rgCh <- rgResult{err: fmt.Errorf("set rg range: %w", serr)}
				return
			}
			obj2, gerr := client.GetObject(ctx, p.Bucket, entry.Name, opts2)
			if gerr != nil {
				rgCh <- rgResult{err: fmt.Errorf("row-group GET: %w", gerr)}
				return
			}
			defer obj2.Close()

			var n int64
			buf := make([]byte, 64*1024)
			for {
				nr, rerr := obj2.Read(buf)
				n += int64(nr)
				if rerr == io.EOF {
					break
				}
				if rerr != nil {
					rgCh <- rgResult{n: n, err: fmt.Errorf("row-group read: %w", rerr)}
					return
				}
				if ctx.Err() != nil {
					rgCh <- rgResult{n: n, err: ctx.Err()}
					return
				}
			}
			rgCh <- rgResult{n: n}
		}(rgStart, rgEnd)
	}

	// Collect row-group results.
	for j := 0; j < rgReads; j++ {
		select {
		case <-ctx.Done():
			// Drain remaining goroutines.
			go func() {
				for k := j; k < rgReads; k++ {
					<-rgCh
				}
			}()
			return totalBytes, firstByte, ctx.Err()
		case r := <-rgCh:
			totalBytes += r.n
			if r.err != nil && err == nil {
				err = r.err
			}
		}
	}

	return totalBytes, firstByte, err
}
