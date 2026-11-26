package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/michaelkage/ForgeOS/worker-host/internal/buildworker"
)

func main() {
	snapshot := flag.String("snapshot", "", "immutable build snapshot JSON")
	digest := flag.String("snapshot-sha256", "", "canonical snapshot SHA-256")
	artifact := flag.String("artifact", "", "artifact output path")
	timeout := flag.Int("timeout-seconds", 0, "maximum wall time from the signed VM bootstrap")
	flag.Parse()
	if *snapshot == "" || *digest == "" || *artifact == "" || *timeout < 60 || *timeout > 172800 {
		fmt.Fprintln(os.Stderr, "snapshot, snapshot-sha256, artifact, and a valid timeout-seconds are required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()
	if err := buildworker.Run(ctx, buildworker.Config{SnapshotPath: *snapshot, ExpectedSHA256: *digest, ArtifactPath: *artifact}); err != nil {
		fmt.Fprintln(os.Stderr, "ForgeOS build failed:", err)
		os.Exit(1)
	}
}
