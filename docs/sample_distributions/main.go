// sample_distributions calls the real GetExpRandSize and GetLogNormalRandSize
// functions from pkg/generator and emits a TSV of samples for each mode.
//
// Usage:
//
//	go run ./docs/sample_distributions -n 100000 -typical 10MiB -sigma 1.0 > docs/dist_samples.tsv
//
// Each output row: mode<TAB>typical_bytes<TAB>max_bytes<TAB>size_bytes
package main

import (
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"

	"github.com/dustin/go-humanize"
	"github.com/minio/warp/pkg/generator"
)

func mustParseBytes(s string) int64 {
	v, err := humanize.ParseBytes(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid size %q: %v\n", s, err)
		os.Exit(1)
	}
	return int64(v)
}

func main() {
	n := flag.Int("n", 100_000, "number of samples per distribution")
	typicalStr := flag.String("typical", "10MiB", "--obj.size value (typical size users specify)")
	sigma := flag.Float64("sigma", 1.0, "lognormal sigma (log-space std dev)")
	seed := flag.Int64("seed", 42, "RNG seed")
	flag.Parse()

	typical := mustParseBytes(*typicalStr)

	// Mirror the cli/generator.go logic exactly.
	// log₂:      --obj.size = target average → max = typical / 0.179151
	// lognormal: --obj.size = target median  → max = typical × 10
	const log2AvgFactor = 0.179151
	maxLog2 := int64(math.Round(float64(typical) / log2AvgFactor))
	maxLogn := typical * 10

	rng := rand.New(rand.NewSource(*seed))

	// Header
	fmt.Printf("mode\ttypical_bytes\tmax_bytes\tsize_bytes\n")

	// Mirror the Options.getSize() call exactly: minSize defaults to 0 when using WithSize().
	const minSize int64 = 0

	// --- log₂ samples (calls the real GetExpRandSize) ---
	for i := 0; i < *n; i++ {
		sz := generator.GetExpRandSize(rng, minSize, maxLog2)
		fmt.Printf("log2\t%d\t%d\t%d\n", typical, maxLog2, sz)
	}

	// --- lognormal samples (calls the real GetLogNormalRandSize) ---
	sigmaVal := *sigma
	for i := 0; i < *n; i++ {
		sz := generator.GetLogNormalRandSize(rng, minSize, maxLogn, sigmaVal)
		fmt.Printf("logn\t%d\t%d\t%d\n", typical, maxLogn, sz)
	}

	// Print summary to stderr
	fmt.Fprintf(os.Stderr, "\nInputs:\n")
	fmt.Fprintf(os.Stderr, "  --obj.size (typical) = %s (%d bytes)\n", *typicalStr, typical)
	fmt.Fprintf(os.Stderr, "  sigma                = %.2f\n", sigmaVal)
	fmt.Fprintf(os.Stderr, "  n                    = %d\n", *n)
	fmt.Fprintf(os.Stderr, "\nComputed maxima (matches cli/generator.go):\n")
	fmt.Fprintf(os.Stderr, "  log₂  max = %s  (typical / %.6f)\n", fmtBytes(maxLog2), log2AvgFactor)
	fmt.Fprintf(os.Stderr, "  logn  max = %s  (typical × 10)\n", fmtBytes(maxLogn))
	fmt.Fprintf(os.Stderr, "\nTo plot:\n")
	fmt.Fprintf(os.Stderr, "  go run ./docs/sample_distributions -typical %s > docs/dist_samples.tsv\n", *typicalStr)
	fmt.Fprintf(os.Stderr, "  python docs/plot_randsize.py\n")
}

func fmtBytes(n int64) string {
	return humanize.IBytes(uint64(n))
}
