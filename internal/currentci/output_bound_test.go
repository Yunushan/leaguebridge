package currentci

import (
	"io"
	"strings"
	"testing"
)

// os/exec uses io.Copy for non-file stdout/stderr destinations. Hide the
// source's WriterTo method to exercise the destination's ReaderFrom fast path.
func TestSubprocessOutputLimitCannotBeBypassedByIOCopy(t *testing.T) {
	output := &boundedOutput{}
	reader := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", maximumResponse+1))}
	if _, exposed := any(output).(io.ReaderFrom); exposed {
		t.Fatal("bounded output exposes an unbounded ReaderFrom fast path")
	}
	if _, err := io.Copy(output, reader); err == nil {
		t.Fatal("oversized subprocess-style pipe copy succeeded")
	}
	if output.Len() > maximumResponse {
		t.Fatalf("retained %d bytes beyond output limit", output.Len())
	}
}
