package smite

import (
	"io"
	"log"
	"os"
)

// LocalRunner reads fuzz input from the SMITE_INPUT environment variable
// or from stdin. This runner is used for reproducing test cases locally
// without using the Nyx hypervisor.
type LocalRunner struct {
	input []byte
}

// NewLocalRunner creates a new LocalRunner instance.
func NewLocalRunner() (*LocalRunner, error) {
	return &LocalRunner{}, nil
}

// GetFuzzInput retrieves the fuzz input from SMITE_INPUT env var or stdin.
// The input is cached after the first call.
func (r *LocalRunner) GetFuzzInput() []byte {
	if r.input != nil {
		return r.input
	}

	fuzzInputPath := os.Getenv("SMITE_INPUT")

	if fuzzInputPath != "" {
		// Read from file
		data, err := os.ReadFile(fuzzInputPath)
		if err != nil {
			log.Printf("Warning: Failed to read %s: %v", fuzzInputPath, err)
			r.input = []byte{}
			return r.input
		}
		r.input = data
		return r.input
	}

	// Read from stdin
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Printf("Warning: Failed to read from stdin: %v", err)
		r.input = []byte{}
		return r.input
	}

	r.input = data
	return r.input
}

// Fail logs the failure message.
func (r *LocalRunner) Fail(message string) {
	log.Printf("Error: %s", message)
}

// Skip logs that the test case is being skipped.
func (r *LocalRunner) Skip() {
	log.Println("Warning: Skipping test case")
}

// Close performs cleanup. For LocalRunner, this is a no-op.
func (r *LocalRunner) Close() error {
	return nil
}
