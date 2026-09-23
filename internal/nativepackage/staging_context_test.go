package nativepackage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStagingReadStopsAfterContextCancellation(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "payload.bin"), bytes.Repeat([]byte("p"), 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx := &cancelAfterContextChecks{Context: context.Background(), cancelAt: 4}
	data, info, err := readStagedFileContext(ctx, root, "payload.bin", MaximumPayloadSize)
	if !errors.Is(err, context.Canceled) || data != nil || info != nil || ctx.checks < ctx.cancelAt {
		t.Fatalf("staging read did not stop during payload transfer: bytes=%d info=%v checks=%d err=%v", len(data), info, ctx.checks, err)
	}
}

func TestStagingDigestStopsAfterContextCancellation(t *testing.T) {
	ctx := &cancelAfterContextChecks{Context: context.Background(), cancelAt: 3}
	digest, err := digestContext(ctx, bytes.Repeat([]byte("p"), 1<<20))
	if !errors.Is(err, context.Canceled) || digest != "" || ctx.checks < ctx.cancelAt {
		t.Fatalf("staging digest did not stop during hashing: digest=%q checks=%d err=%v", digest, ctx.checks, err)
	}
}

func TestVerifyStagingRootContextRejectsCanceledContext(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyStagingRootContext(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled staging verification returned %v", err)
	}
	if _, err := VerifyStagingRootContext(nil, root); err == nil {
		t.Fatal("nil staging verification context was accepted")
	}
}

type cancelAfterContextChecks struct {
	context.Context
	checks   int
	cancelAt int
}

func (value *cancelAfterContextChecks) Err() error {
	value.checks++
	if value.checks >= value.cancelAt {
		return context.Canceled
	}
	return nil
}
