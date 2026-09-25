package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRunRequiresOnePackageAndStagingTree(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-package", "/tmp/package.deb"},
		{"-staging", "/tmp/staging"},
		{"-package", "/tmp/package.deb", "-staging", "/tmp/staging", "extra"},
	} {
		var output bytes.Buffer
		if err := run(context.Background(), args, &output); err == nil || output.Len() != 0 {
			t.Fatalf("invalid arguments %q accepted: %q, %v", args, output.String(), err)
		}
	}
}

func TestRunPropagatesCancellationWithoutSuccessOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	err := run(ctx, []string{"-package", "package.deb", "-staging", "staging"}, &output)
	if !errors.Is(err, context.Canceled) || strings.Contains(output.String(), "verified") {
		t.Fatalf("canceled payload check = %q, %v", output.String(), err)
	}
}
