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
	"github.com/minio/cli"
	"github.com/minio/pkg/v3/console"
	"github.com/minio/warp/pkg/bench"
)

var parquetFlags = []cli.Flag{
	cli.IntFlag{
		Name:  "objects",
		Value: 100,
		Usage: "Number of Parquet objects to upload during the prepare phase.",
	},
	cli.StringFlag{
		Name:  "obj.size",
		Value: "128MiB",
		Usage: "Size of each Parquet object. Supports human-friendly sizes: 64MiB, 1GiB, etc.",
	},
	cli.IntFlag{
		Name:  "row-groups",
		Value: 10,
		Usage: "Number of row groups to embed in each Parquet object.",
	},
	cli.StringFlag{
		Name:  "rg-size",
		Value: "8MiB",
		Usage: "Byte size of each row group. Supports human-friendly sizes: 4MiB, 16MiB, etc.",
	},
	cli.StringFlag{
		Name:  "footer-size",
		Value: "128KiB",
		Usage: "Bytes to fetch in the footer read phase (last N bytes of the object).",
	},
	cli.IntFlag{
		Name:  "rg-reads",
		Value: 2,
		Usage: "Number of parallel row-group byte-range GETs per benchmark operation.",
	},
	cli.BoolFlag{
		Name: "rg-sequential",
		Usage: "Read --rg-reads consecutive row groups starting at a random offset " +
			"instead of the default random-without-replacement selection. " +
			"Use this to model sequential file-major access patterns (e.g. DLRM training).",
	},
	cli.BoolFlag{
		Name:  "list-existing",
		Usage: "Skip the upload phase; use objects already in the bucket as the GET corpus.",
	},
}

// ParquetCombinedFlags is exported so the run command can reference it.
var ParquetCombinedFlags = combineFlags(globalFlags, ioFlags, parquetFlags, genFlags, benchFlags, analyzeFlags)

// parquetCmd is the 'warp parquet' CLI command.
var parquetCmd = cli.Command{
	Name:   "parquet",
	Usage:  "benchmark Parquet object creation and schema-aware range GETs",
	Action: mainParquet,
	Before: setGlobalsFromContext,
	Flags:  ParquetCombinedFlags,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} [FLAGS]

DESCRIPTION:
  The parquet benchmark exercises the full AI/ML Parquet I/O pattern:

  Prepare phase
    Upload --objects structurally valid Parquet files.  Each file has a real
    PAR1 magic header, --row-groups row groups of --rg-size bytes, and a valid
    Thrift CompactProtocol FileMetaData footer with accurate row-group byte
    offsets.

  Benchmark loop (each goroutine, repeated until --duration expires)
    1. Footer read  — byte-range GET of the last --footer-size bytes.
    2. Footer parse — decode the Thrift FileMetaData to extract row-group
       offsets.  This verifies the server returned the real footer bytes (not
       synthesized random data), which is the key correctness check for
       s3-ultra's Parquet footer storage feature.
    3. Row-group GETs — --rg-reads parallel byte-range GETs.  By default, row
       groups are selected randomly *without replacement* so each read in a
       single operation hits a distinct row group.  With --rg-sequential, warp
       picks --rg-reads *consecutive* row groups starting at a random offset,
       modeling the DLRM/file-major sequential access pattern.

  Metrics
    Each benchmark op records the total byte count (footer + all row groups)
    and TTFB from the first footer read byte.

EXAMPLES:
  # Basic test against s3-ultra on localhost:
  warp parquet --host localhost:9000 --access-key minioadmin --secret-key minioadmin \
    --bucket parquet-test --objects 50 --obj.size 128MiB \
    --row-groups 10 --rg-size 8MiB --footer-size 128KiB --rg-reads 2

  # Test with existing objects (e.g. real Parquet files already uploaded):
  warp parquet --host localhost:9000 --access-key minioadmin --secret-key minioadmin \
    --bucket my-bucket --list-existing --rg-reads 4

  # High-concurrency stress test:
  warp parquet --host localhost:9000 --access-key minioadmin --secret-key minioadmin \
    --bucket parquet-bench --objects 200 --obj.size 256MiB \
    --concurrent 32 --duration 5m --rg-reads 4

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}`,
}

// mainParquet is the entry point for the 'warp parquet' command.
func mainParquet(ctx *cli.Context) error {
	checkParquetSyntax(ctx)

	objSize, err := toSize(ctx.String("obj.size"))
	if err != nil {
		return err
	}
	rgSize, err := toSize(ctx.String("rg-size"))
	if err != nil {
		return err
	}
	footerSize, err := toSize(ctx.String("footer-size"))
	if err != nil {
		return err
	}

	b := bench.Parquet{
		Common:        getCommon(ctx, newGenSource(ctx, "obj.size")),
		CreateObjects: ctx.Int("objects"),
		ObjSize:       int64(objSize),
		RowGroupCount: ctx.Int("row-groups"),
		RowGroupSize:  int64(rgSize),
		FooterSize:    int64(footerSize),
		RGReads:       ctx.Int("rg-reads"),
		RGSequential:  ctx.Bool("rg-sequential"),
		ListExisting:  ctx.Bool("list-existing"),
		ListPrefix:    ctx.String("prefix"),
	}
	return runBench(ctx, &b)
}

func checkParquetSyntax(ctx *cli.Context) {
	if ctx.NArg() > 0 {
		console.Fatal("Command takes no arguments")
	}
	if !ctx.Bool("list-existing") && ctx.Int("objects") < 1 {
		console.Fatal("At least one object must be specified (--objects)")
	}
	if ctx.Int("row-groups") < 1 {
		console.Fatal("At least one row group must be specified (--row-groups)")
	}
	if ctx.Int("rg-reads") < 1 {
		console.Fatal("At least one row-group read must be specified (--rg-reads)")
	}
	checkAnalyze(ctx)
	checkBenchmark(ctx)
}
