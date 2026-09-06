package remote

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

const maximumControlOutput = 64 << 10

// Embedded through v2.7.1 exits zero even when pairing or unpairing fails.
// Its success message, rather than its exit status alone, confirms completion.
// Capture each stream separately because os/exec may write them concurrently.
type controlCapture struct {
	buffer    bytes.Buffer
	truncated bool
}

func (c *controlCapture) Write(data []byte) (int, error) {
	n := len(data)
	remaining := maximumControlOutput - c.buffer.Len()
	if n > remaining {
		data = data[:remaining]
		c.truncated = true
	}
	_, _ = c.buffer.Write(data)
	return n, nil
}

func captureControlOutput(output io.Writer, capture *controlCapture) io.Writer {
	if output == nil {
		output = io.Discard
	}
	return io.MultiWriter(output, capture)
}

func verifyEmbeddedControl(operation Operation, stdout, stderr *controlCapture) error {
	if stdout.truncated || stderr.truncated {
		return fmt.Errorf("Embedded %s output exceeded the verification limit; completion could not be confirmed", operation)
	}
	verb := "paired"
	if operation == Unpair {
		verb = "unpaired"
	}
	success := false
	for stream, captured := range []*controlCapture{stdout, stderr} {
		for _, line := range strings.Split(captured.buffer.String(), "\n") {
			line = strings.TrimSpace(stripTerminalControlSequences(line))
			if strings.HasPrefix(line, "Failed to "+string(operation)+" to server:") {
				return fmt.Errorf("Embedded reported that %s failed; check the client output and physical host", operation)
			}
			// The misspelling is the released Embedded success message. Accept
			// the corrected spelling too, but never diagnostic stderr alone.
			if stream == 0 && (line == "Succesfully "+verb || line == "Successfully "+verb) {
				success = true
			}
		}
	}
	if !success {
		return fmt.Errorf("Embedded exited without confirming %s; check the client output and physical host", operation)
	}
	return nil
}
