/*
 * Warp (C) 2019-2024 MinIO, Inc.
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

package aggregate

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// WriteTSV writes segmented throughput data as a TSV report to w.
// Each row represents one time segment for one operation type.
// cmdLine is written as a comment header line.
// Columns: op, start, end, bps, ops_per_sec, errors
func (r *Realtime) WriteTSV(w io.Writer, cmdLine string) error {
	if r == nil {
		return nil
	}
	if cmdLine != "" {
		if _, err := fmt.Fprintf(w, "# %s\n", cmdLine); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "op\tstart\tend\tbps\tops_per_sec\terrors"); err != nil {
		return err
	}

	opTypes := make([]string, 0, len(r.ByOpType))
	for k := range r.ByOpType {
		opTypes = append(opTypes, k)
	}
	sort.Strings(opTypes)

	for _, op := range opTypes {
		agg := r.ByOpType[op]
		if agg == nil {
			continue
		}
		if err := writeSegmentsTSV(w, op, &agg.Throughput); err != nil {
			return err
		}
	}
	return writeSegmentsTSV(w, "TOTAL", &r.Total.Throughput)
}

func writeSegmentsTSV(w io.Writer, opName string, t *Throughput) error {
	if t == nil || t.Segmented == nil || len(t.Segmented.Segments) == 0 {
		return nil
	}
	segs := make(SegmentsSmall, len(t.Segmented.Segments))
	copy(segs, t.Segmented.Segments)
	segs.SortByStartTime()
	segDur := time.Duration(t.Segmented.SegmentDurationMillis) * time.Millisecond
	for _, seg := range segs {
		end := seg.Start.Add(segDur)
		_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%.0f\t%.3f\t%d\n",
			opName,
			seg.Start.UTC().Format(time.RFC3339),
			end.UTC().Format(time.RFC3339),
			seg.BPS,
			seg.OPS,
			seg.Errors,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
