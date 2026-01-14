package smite

import (
	"os"
)

// StdRunner automatically selects the appropriate runner backend.
// It uses NyxRunner if SMITE_NYX=1, otherwise falls back to LocalRunner.
type StdRunner struct {
	runner Runner
	isNyx  bool
}

// NewStdRunner creates a new StdRunner that automatically selects
// the appropriate backend based on the SMITE_NYX environment variable.
// If SMITE_NYX=1, uses NyxRunner, otherwise uses LocalRunner.
func NewStdRunner() (*StdRunner, error) {
	// Check SMITE_NYX environment variable
	if os.Getenv("SMITE_NYX") == "1" {
		nyxRunner, err := tryNewNyxRunner()
		if err != nil {
			return nil, err
		}
		return &StdRunner{
			runner: nyxRunner,
			isNyx:  true,
		}, nil
	}

	// Use LocalRunner
	localRunner, err := NewLocalRunner()
	if err != nil {
		return nil, err
	}

	return &StdRunner{
		runner: localRunner,
		isNyx:  false,
	}, nil
}

// GetFuzzInput retrieves the next fuzz input using the selected backend.
func (s *StdRunner) GetFuzzInput() []byte {
	return s.runner.GetFuzzInput()
}

// Fail marks the test case as failed with the given error message.
func (s *StdRunner) Fail(message string) {
	s.runner.Fail(message)
}

// Skip skips the current test case.
func (s *StdRunner) Skip() {
	s.runner.Skip()
}

// Close performs cleanup after running the test case.
func (s *StdRunner) Close() error {
	return s.runner.Close()
}

// IsNyx returns true if using the Nyx backend, false if using LocalRunner.
func (s *StdRunner) IsNyx() bool {
	return s.isNyx
}
