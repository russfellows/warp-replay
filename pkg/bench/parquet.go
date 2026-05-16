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
//     offsets (verifies the server returned the real footer, not synthesized bytes).
//     c. Row-group GETs — --rg-reads parallel byte-range GETs, each hitting one
//     randomly chosen row group at its actual byte offset.
//
// When run against s3-ultra this validates:
//   - That s3-ultra correctly captured the Parquet footer on PUT.
//   - That range GETs of the footer region return real footer bytes (not
//     synthesized random data).
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
	RGSequential  bool   // pick RGReads consecutive RGs starting at a random offset (default: random without replacement)
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

// prepareFromExisting lists objects already in the bucket, then concurrently
// fetches and caches the Parquet footer for every object.  Caching footers
// once at startup — rather than re-fetching on every benchmark iteration —
// matches the behavior of real AI/ML data loaders (e.g. PyArrow, TensorStore,
// mosaic-streaming) which parse metadata once and reuse it across epochs.
//
// Both the LIST operation and each footer GET are recorded to the Collector so
// they appear in the --full op-log alongside the benchmark GETs.
func (p *Parquet) prepareFromExisting(ctx context.Context) error {
	rcv := p.Collector.Receiver()

	// ── LIST ─────────────────────────────────────────────────────────────────
	listOp := Operation{
		OpType:   "LIST",
		Thread:   0,
		ObjPerOp: 1,
	}
	listOp.Start = time.Now()
	objs, err := p.listExistingObjects(ctx, ListObjectsConfig{
		Bucket:         p.Bucket,
		Prefix:         p.ListPrefix,
		CreateObjects:  p.CreateObjects,
		FilterZeroSize: true,
	})
	listOp.End = time.Now()
	if cl, done := p.Client(); true {
		listOp.Endpoint = cl.EndpointURL().String()
		done()
	}
	listOp.ObjPerOp = len(objs)
	if err != nil {
		listOp.Err = err.Error()
		rcv <- listOp
		return err
	}
	rcv <- listOp

	entries := make([]parquetEntry, len(objs))
	for i, o := range objs {
		entries[i] = parquetEntry{Name: o.Name, Size: o.Size}
	}

	// ── Concurrently pre-fetch footers ──────────────────────────────────────
	//
	// We use a bounded worker pool (min(len, concurrency)) so we don't open
	// more connections than the benchmark phase would use.
	workers := p.Concurrency
	if workers > len(entries) {
		workers = len(entries)
	}
	if workers < 1 {
		workers = 1
	}

	p.UpdateStatus(fmt.Sprintf("Pre-fetching Parquet footers for %d objects...", len(entries)))

	type work struct{ idx int }
	workCh := make(chan work, len(entries))
	for i := range entries {
		workCh <- work{i}
	}
	close(workCh)

	var (
		mu       sync.Mutex
		fetchWg  sync.WaitGroup
		fetchErr error
		cached   int
	)

	footerSize := p.FooterSize
	if footerSize <= 0 {
		footerSize = 131072 // 128 KiB default
	}

	fetchWg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer fetchWg.Done()
			for job := range workCh {
				select {
				case <-ctx.Done():
					return
				default:
				}

				entry := &entries[job.idx]
				objSize := entry.Size

				// Phase 1: try with the configured footer buffer.
				fs := footerSize
				if fs > objSize {
					fs = objSize
				}
				start := objSize - fs

				opts := minio.GetObjectOptions{}
				if serr := opts.SetRange(start, objSize-1); serr != nil {
					continue // skip un-parseable object
				}

				client, cldone := p.Client()

				// Record this footer GET to the op-log.
				footerOp := Operation{
					OpType:   "GET-FOOTER",
					Thread:   0,
					File:     entry.Name,
					ObjPerOp: 1,
					Endpoint: client.EndpointURL().String(),
				}
				footerOp.Start = time.Now()

				obj, gerr := client.GetObject(ctx, p.Bucket, entry.Name, opts)
				if gerr != nil {
					footerOp.End = time.Now()
					footerOp.Err = gerr.Error()
					rcv <- footerOp
					cldone()
					continue
				}
				buf := make([]byte, fs)
				ttfbRecorded := false
				n := 0
				for n < int(fs) {
					nr, rerr := obj.Read(buf[n:])
					if !ttfbRecorded && nr > 0 {
						t := time.Now()
						footerOp.FirstByte = &t
						ttfbRecorded = true
					}
					n += nr
					if rerr == io.EOF {
						break
					}
					if rerr != nil {
						break
					}
				}
				obj.Close()
				cldone()

				footerOp.End = time.Now()
				footerOp.Size = int64(n)
				rcv <- footerOp

				groups, parseErr := ParseParquetFooter(buf[:n], objSize)
				if parseErr != nil {
					// Footer buffer too small — extract the required size from
					// the error message and retry with the exact footer.
					// ParseParquetFooter always includes the needed length in
					// the error text ("increase --footer-size to at least N bytes").
					var needed int64
					if _, scanErr := fmt.Sscanf(parseErr.Error(),
						"metadata length %d exceeds", &needed); scanErr == nil && needed > 0 {
						needed += 8 // include the 4-byte length + 4-byte PAR1 magic
						retryStart := objSize - needed
						if retryStart < 0 {
							retryStart = 0
							needed = objSize
						}
						opts2 := minio.GetObjectOptions{}
						if serr := opts2.SetRange(retryStart, objSize-1); serr == nil {
							client2, cldone2 := p.Client()

							retryOp := Operation{
								OpType:   "GET-FOOTER",
								Thread:   0,
								File:     entry.Name,
								ObjPerOp: 1,
								Endpoint: client2.EndpointURL().String(),
							}
							retryOp.Start = time.Now()

							obj2, gerr2 := client2.GetObject(ctx, p.Bucket, entry.Name, opts2)
							if gerr2 == nil {
								buf2 := make([]byte, needed)
								n2, _ := io.ReadFull(obj2, buf2)
								obj2.Close()
								retryOp.End = time.Now()
								retryOp.Size = int64(n2)
								rcv <- retryOp
								groups, _ = ParseParquetFooter(buf2[:n2], objSize)
							} else {
								retryOp.End = time.Now()
								retryOp.Err = gerr2.Error()
								rcv <- retryOp
							}
							cldone2()
						}
					}
				}

				if len(groups) > 0 {
					entry.Groups = groups
					mu.Lock()
					cached++
					mu.Unlock()
				}
			}
		}()
	}
	fetchWg.Wait()

	if fetchErr != nil {
		return fetchErr
	}

	p.UpdateStatus(fmt.Sprintf("Cached row-group layout for %d/%d objects", cached, len(entries)))
	p.objects = entries
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
// Each goroutine loops until ctx is canceled.  One iteration consists of:
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

	// Non-cancellable context for operations in flight when ctx is canceled;
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

				// Each row-group GET is recorded as its own Operation inside
				// doParquetGet so the trace exactly reflects every HTTP request.
				if err := p.doParquetGet(ctx, client, rng, entry, rcv, uint32(threadIdx)); err != nil {
					p.Error("parquet get error:", err)
				}
				cldone()
			}
		}(i)
	}

	wg.Wait()
	return nil
}

// doParquetGet performs the Parquet GET benchmark for one object.
//
// When the object's row-group layout was pre-fetched during Prepare (the normal
// path for --list-existing), the footer GET is skipped entirely and we go
// straight to Phase 3 row-group GETs.  This matches the behavior of real
// AI/ML data loaders that cache Parquet metadata and only issue row-group reads
// during training.
//
// When the layout is NOT cached (e.g. objects were uploaded during this run
// but the footer was not stored), we fall back to the three-phase approach:
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
	rcv chan<- Operation,
	threadIdx uint32,
) error {
	groups := entry.Groups // may be nil if footer was not pre-cached
	objSize := entry.Size

	// ── Phase 1 + 2: footer fetch (skipped when cache is warm) ──────────────
	if len(groups) == 0 {
		footerSize := p.FooterSize
		if footerSize <= 0 {
			footerSize = 131072 // 128 KiB default
		}

		footerStart := objSize - footerSize
		if footerStart < 0 {
			footerStart = 0
			footerSize = objSize
		}

		footerOpts := minio.GetObjectOptions{}
		if err2 := footerOpts.SetRange(footerStart, objSize-1); err2 != nil {
			return fmt.Errorf("set footer range: %w", err2)
		}

		footerObj, err2 := client.GetObject(ctx, p.Bucket, entry.Name, footerOpts)
		if err2 != nil {
			return fmt.Errorf("footer GET: %w", err2)
		}

		footerBuf := make([]byte, footerSize)
		var footerRead int
		for footerRead < int(footerSize) {
			nr, rerr := footerObj.Read(footerBuf[footerRead:])
			footerRead += nr
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				footerObj.Close()
				return fmt.Errorf("footer read: %w", rerr)
			}
			select {
			case <-ctx.Done():
				footerObj.Close()
				return ctx.Err()
			default:
			}
		}
		footerObj.Close()

		var parseErr error
		groups, parseErr = ParseParquetFooter(footerBuf[:footerRead], objSize)
		if parseErr != nil && parseErr != ErrNotParquet {
			return fmt.Errorf("ParseParquetFooter(%s): %w", entry.Name, parseErr)
		}
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

	// Build the list of (start, end) byte ranges for this operation.
	//
	// When row-group metadata is available, two modes are supported:
	//
	//   Default (--rg-sequential=false):
	//     Sample rgReads distinct row groups without replacement using a
	//     partial Fisher-Yates shuffle.  This avoids reading the same row
	//     group twice in one op, which would skew throughput numbers upward
	//     on a server with object caching.
	//
	//   Sequential (--rg-sequential=true):
	//     Pick rgReads consecutive row groups starting at a random offset.
	//     This models the DLRM/file-major access pattern where an epoch
	//     reads each file sequentially from RG 0 to RG N.
	//
	// When no metadata is available (groups is nil), fall back to a single
	// random range of RowGroupSize bytes.
	type byteRange struct{ start, end int64 }
	var ranges []byteRange

	if len(groups) > 0 {
		n := rgReads
		if n > len(groups) {
			n = len(groups)
		}

		if p.RGSequential {
			// Sequential: pick a random starting RG, then take n consecutive ones
			// (wrapping is not done; clamp to end of file instead).
			startIdx := rng.Intn(len(groups))
			endIdx := startIdx + n
			if endIdx > len(groups) {
				endIdx = len(groups)
			}
			for _, rg := range groups[startIdx:endIdx] {
				end := rg.Offset + rg.Size - 1
				if end >= objSize {
					end = objSize - 1
				}
				ranges = append(ranges, byteRange{rg.Offset, end})
			}
		} else {
			// Random without replacement: partial Fisher-Yates shuffle over indices.
			indices := make([]int, len(groups))
			for i := range indices {
				indices[i] = i
			}
			for i := 0; i < n; i++ {
				j := i + rng.Intn(len(indices)-i)
				indices[i], indices[j] = indices[j], indices[i]
				rg := groups[indices[i]]
				end := rg.Offset + rg.Size - 1
				if end >= objSize {
					end = objSize - 1
				}
				ranges = append(ranges, byteRange{rg.Offset, end})
			}
		}
	} else {
		// No row-group metadata: fall back to a single random range of RowGroupSize.
		rgSize := p.RowGroupSize
		if rgSize <= 0 {
			rgSize = 8 * 1024 * 1024 // 8 MiB default
		}
		var start, end int64
		if rgSize >= objSize {
			start, end = 0, objSize-1
		} else {
			start = rng.Int63n(objSize - rgSize)
			end = start + rgSize - 1
		}
		ranges = append(ranges, byteRange{start, end})
	}

	// Issue all ranges concurrently.  Each goroutine records its own Operation
	// so the trace contains exactly one row per HTTP byte-range GET.
	actualReads := len(ranges)

	type rgResult struct {
		err error
	}
	rgCh := make(chan rgResult, actualReads)

	endpoint := client.EndpointURL().String()
	fileName := entry.Name
	if p.DiscardOutput {
		fileName = ""
	}

	for j := 0; j < actualReads; j++ {
		r := ranges[j]
		rgStart, rgEnd := r.start, r.end

		go func(start, end int64) {
			op := Operation{
				OpType:   http.MethodGet,
				Thread:   threadIdx,
				File:     fileName,
				ObjPerOp: 1,
				Endpoint: endpoint,
			}
			op.Start = time.Now()

			opts2 := minio.GetObjectOptions{}
			if serr := opts2.SetRange(start, end); serr != nil {
				op.End = time.Now()
				op.Err = fmt.Sprintf("set rg range: %v", serr)
				rcv <- op
				rgCh <- rgResult{err: fmt.Errorf("set rg range: %w", serr)}
				return
			}
			obj2, gerr := client.GetObject(ctx, p.Bucket, entry.Name, opts2)
			if gerr != nil {
				op.End = time.Now()
				op.Err = fmt.Sprintf("row-group GET: %v", gerr)
				rcv <- op
				rgCh <- rgResult{err: fmt.Errorf("row-group GET: %w", gerr)}
				return
			}
			defer obj2.Close()

			var n int64
			ttfbRecorded := false
			buf := make([]byte, 64*1024)
			for {
				nr, rerr := obj2.Read(buf)
				if !ttfbRecorded && nr > 0 {
					t := time.Now()
					op.FirstByte = &t
					ttfbRecorded = true
				}
				n += int64(nr)
				if rerr == io.EOF {
					break
				}
				if rerr != nil {
					op.End = time.Now()
					op.Size = n
					op.Err = fmt.Sprintf("row-group read: %v", rerr)
					rcv <- op
					rgCh <- rgResult{err: fmt.Errorf("row-group read: %w", rerr)}
					return
				}
				if ctx.Err() != nil {
					op.End = time.Now()
					op.Size = n
					op.Err = ctx.Err().Error()
					rcv <- op
					rgCh <- rgResult{err: ctx.Err()}
					return
				}
			}
			op.End = time.Now()
			op.Size = n
			rcv <- op
			rgCh <- rgResult{}
		}(rgStart, rgEnd)
	}

	// Collect results and surface the first error.
	var firstErr error
	for j := 0; j < actualReads; j++ {
		select {
		case <-ctx.Done():
			// Drain all remaining goroutines synchronously before returning.
			// Each goroutine sends to rcv before signaling rgCh, so waiting
			// here guarantees no goroutine will send to rcv after this function
			// returns and the caller closes the collector.
			for k := j; k < actualReads; k++ {
				<-rgCh
			}
			return ctx.Err()
		case r := <-rgCh:
			if r.err != nil && firstErr == nil {
				firstErr = r.err
			}
		}
	}

	return firstErr
}
