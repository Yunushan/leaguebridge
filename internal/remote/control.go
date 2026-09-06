package remote

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
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

type serializedControlWriter struct {
	mutex  *sync.Mutex
	writer io.Writer
}

func (w serializedControlWriter) Write(data []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.writer.Write(data)
}

func captureControlOutputs(stdout, stderr io.Writer, stdoutCapture, stderrCapture *controlCapture) (io.Writer, io.Writer) {
	// Separate captures give os/exec distinct writers even when both original
	// destinations are the same. Preserve its same-destination serialization
	// with one lock for this invocation, without comparing arbitrary writers.
	mutex := &sync.Mutex{}
	wrap := func(output io.Writer, capture *controlCapture) io.Writer {
		if output == nil {
			output = io.Discard
		}
		return serializedControlWriter{mutex: mutex, writer: io.MultiWriter(output, capture)}
	}
	return wrap(stdout, stdoutCapture), wrap(stderr, stderrCapture)
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
