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

package cli

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/minio/mc/pkg/probe"

	"github.com/minio/cli"
	"github.com/minio/warp/pkg/generator"

	hist "github.com/jfsmig/prng/histogram"
)

var genFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "obj.generator",
		Value: "random",
		Usage: "Use specific data generator",
	},
	cli.BoolFlag{
		Name: "obj.randsize",
		Usage: "Randomize object sizes using the log\u2082 distribution. --obj.size is the target average; " +
			"warp computes the maximum internally (~5.6\u00d7 the average). " +
			"Use --obj.size=min,max to set bounds explicitly instead.",
	},
	cli.BoolFlag{
		Name: "obj.rand-log2",
		Usage: "Randomize object sizes using the log\u2082 distribution (equal count per doubling). " +
			"--obj.size is the target average. Alias for --obj.randsize.",
	},
	cli.BoolFlag{
		Name: "obj.rand-logn",
		Usage: "Randomize object sizes using a lognormal distribution (bell curve in log-space, realistic workloads). " +
			"--obj.size is the target median; warp computes the maximum internally (median \u00d7 10). " +
			"Use --obj.size=min,max to set bounds explicitly instead.",
	},
	cli.Float64Flag{
		Name:  "obj.randsize.sigma",
		Value: 0,
		Usage: "Log-space standard deviation for the lognormal distribution (--obj.rand-logn). " +
			"Typical values: 0.75 (narrow), 1.0 (default, ~9 doublings), 1.5 (wide).",
	},
}

// newGenSource returns a new generator
func newGenSource(ctx *cli.Context, sizeField string) func() generator.Source {
	prefixSize := 8
	if ctx.Bool("noprefix") {
		prefixSize = 0
	}

	var g generator.OptionApplier
	switch ctx.String("obj.generator") {
	case "random":
		g = generator.WithRandomData()
	default:
		err := errors.New("unknown generator type:" + ctx.String("obj.generator"))
		fatal(probe.NewError(err), "Invalid -generator parameter")
		return nil
	}
	opts := []generator.Option{
		generator.WithCustomPrefix(ctx.String("prefix")),
		generator.WithPrefixSize(prefixSize),
	}
	if strings.IndexRune(ctx.String(sizeField), ':') > 0 {
		if _, err := hist.ParseCSV(ctx.String(sizeField)); err != nil {
			fatalIf(probe.NewError(err), "Invalid histogram format for the size parameter")
		} else {
			opts = append(opts, generator.WithSizeHistograms(ctx.String(sizeField)))
		}
	} else {
		// Determine which random-size mode is active (if any).
		// --obj.rand-logn takes priority over the log₂ flags.
		randLogn := ctx.Bool("obj.rand-logn")
		randLog2 := ctx.Bool("obj.randsize") || ctx.Bool("obj.rand-log2")

		tokens := strings.Split(ctx.String(sizeField), ",")
		switch len(tokens) {
		case 1:
			// Single value: --obj.size is the TYPICAL size (not the maximum).
			//   log₂:      typical = average ≈ max × 0.179151 → max = typical / 0.179151
			//   lognormal: typical = median  = max / 10       → max = typical × 10
			//   fixed:     typical = exact size (no change)
			typical, err := toSize(tokens[0])
			if err != nil {
				fatalIf(probe.NewError(err), "Invalid obj.size specified")
			}
			switch {
			case randLogn:
				maxSize := int64(typical) * 10
				opts = append(opts, generator.WithSize(maxSize),
					generator.WithRandomSizeMode("logn"),
					generator.WithRandomSizeSigma(ctx.Float64("obj.randsize.sigma")))
			case randLog2:
				// log₂ average factor: E[size]/max ≈ 0.179151
				maxSize := int64(math.Round(float64(typical) / 0.179151))
				opts = append(opts, generator.WithSize(maxSize),
					generator.WithRandomSizeMode("log2"))
			default:
				opts = append(opts, generator.WithSize(int64(typical)))
			}
		case 2:
			// Two-value form min,max: user is specifying bounds explicitly — no transformation.
			minSize, err := toSize(tokens[0])
			if err != nil {
				fatalIf(probe.NewError(err), "Invalid min obj.size specified")
			}
			maxSize, err := toSize(tokens[1])
			if err != nil {
				fatalIf(probe.NewError(err), "Invalid max obj.size specified")
			}
			opts = append(opts, generator.WithMinMaxSize(int64(minSize), int64(maxSize)))
			switch {
			case randLogn:
				opts = append(opts, generator.WithRandomSizeMode("logn"),
					generator.WithRandomSizeSigma(ctx.Float64("obj.randsize.sigma")))
			case randLog2:
				opts = append(opts, generator.WithRandomSizeMode("log2"))
			}
		default:
			fatalIf(probe.NewError(fmt.Errorf("unexpected obj.size specified: %s", ctx.String(sizeField))), "Invalid obj.size parameter")
		}
		opts = append([]generator.Option{g.Apply()}, opts...)
	}

	src, err := generator.NewFn(opts...)
	fatalIf(probe.NewError(err), "Unable to create data generator")
	return src
}

// toSize converts a size indication to bytes.
func toSize(size string) (uint64, error) {
	return humanize.ParseBytes(size)
}

// objSize reports the largest object the generator may produce, so a buffer
// pool can be sized before the run. Ranges and histograms report their upper
// bound: a pool sized to the largest object never has to grow mid-run, which
// is the whole point of allocating it up front. Returns 0 when the size cannot
// be determined, leaving the caller to fall back.
func objSize(ctx *cli.Context) int64 {
	field := "obj.size"
	if !ctx.IsSet(field) && ctx.String(field) == "" {
		return 0
	}
	tokens := strings.Split(ctx.String(field), ",")
	var largest int64
	for _, t := range tokens {
		sz, err := toSize(strings.TrimSpace(t))
		if err != nil {
			return 0
		}
		if int64(sz) > largest {
			largest = int64(sz)
		}
	}
	return largest
}
