//go:build !nyx

package smite

import "fmt"

// tryNewNyxRunner is a stub when built without nyx support.
func tryNewNyxRunner() (Runner, error) {
	return nil, fmt.Errorf("go bindings built without nyx tag")
}
