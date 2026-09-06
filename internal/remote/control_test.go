package remote

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type controlFailureWriter struct {
	count int
	err   error
}

func (w controlFailureWriter) Write([]byte) (int, error) { return w.count, w.err }

func TestControlOutputPreservesForwardingFailures(t *testing.T) {
	failure := errors.New("destination rejected output")
	for _, test := range []struct {
		name   string
		writer io.Writer
		count  int
		err    error
	}{
		{"error", controlFailureWriter{count: 2, err: failure}, 2, failure},
		{"short write", controlFailureWriter{count: 2}, 2, io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdoutCapture, stderrCapture controlCapture
			stdout, stderr := captureControlOutputs(test.writer, nil, &stdoutCapture, &stderrCapture)
			if n, err := io.WriteString(stdout, "confirmation"); n != test.count || !errors.Is(err, test.err) {
				t.Fatalf("forwarding returned (%d, %v), want (%d, %v)", n, err, test.count, test.err)
			}
			if stdoutCapture.buffer.Len() != 0 || stdoutCapture.truncated {
				t.Fatal("failed forwarding must not become captured confirmation")
			}
			// A failed write must release the shared lock for the other stream.
			if _, err := io.WriteString(stderr, "diagnostic"); err != nil || stderrCapture.buffer.String() != "diagnostic" {
				t.Fatalf("other stream after forwarding failure: %v", err)
			}
		})
	}
}

func TestControlOutputKeepsNilDestinationsAndCapturesIndependent(t *testing.T) {
	var stdoutCapture, stderrCapture controlCapture
	stdout, stderr := captureControlOutputs(nil, nil, &stdoutCapture, &stderrCapture)
	large := strings.Repeat("x", maximumControlOutput+1)
	if n, err := io.WriteString(stdout, large); n != len(large) || err != nil {
		t.Fatalf("bounded stdout write: (%d, %v)", n, err)
	}
	if _, err := io.WriteString(stderr, "diagnostic"); err != nil {
		t.Fatal(err)
	}
	if stdoutCapture.buffer.Len() != maximumControlOutput || !stdoutCapture.truncated {
		t.Fatal("stdout capture lost its bound")
	}
	if stderrCapture.buffer.String() != "diagnostic" || stderrCapture.truncated {
		t.Fatal("stdout overflow changed the separate stderr capture")
	}
}
