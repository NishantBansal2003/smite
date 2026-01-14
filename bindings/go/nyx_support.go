//go:build nyx

package smite

// tryNewNyxRunner creates and returns a NyxRunner.
func tryNewNyxRunner() (Runner, error) {
	return NewNyxRunner()
}
