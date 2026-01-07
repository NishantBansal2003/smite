package smite

// Runner provides an abstraction for running smite test cases in different
// environments (local system, Nyx hypervisor, etc.).
type Runner interface {
	// GetFuzzInput retrieves the next fuzz input.
	GetFuzzInput() []byte

	// Fail marks the test case as failed with the given error message.
	Fail(message string)

	// Skip skips the current test case.
	Skip()

	// Close performs cleanup after running the test case.
	// For NyxRunner, this releases back to the VM snapshot.
	// Returns an error if cleanup fails.
	Close() error
}
