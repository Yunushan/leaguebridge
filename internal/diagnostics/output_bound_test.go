package diagnostics

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestBundleBufferLimitAppliesToIOCopy(t *testing.T) {
	output := &boundedBuffer{max: 32}
	reader := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 33))}
	if _, err := io.Copy(output, reader); !errors.Is(err, errBundleTooBig) {
		t.Fatalf("oversized copy error = %v, want bundle size rejection", err)
	}
	if output.Len() > 32 {
		t.Fatalf("retained %d bytes beyond limit", output.Len())
	}
}
