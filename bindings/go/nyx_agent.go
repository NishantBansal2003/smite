//go:build nyx

package smite

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lnyx_agent -Wl,-rpath,${SRCDIR}/../../target/release
#cgo LDFLAGS: -L${SRCDIR}/../../target/debug -lnyx_agent -Wl,-rpath,${SRCDIR}/../../target/debug

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Forward declarations of Nyx agent C API
size_t nyx_init(void);
void nyx_dump_file_to_host(const char *file_name, size_t file_name_len,
                           const uint8_t *data, size_t len);
size_t nyx_get_fuzz_input(const uint8_t *data, size_t max_size);
void nyx_skip(void);
void nyx_release(void);
void nyx_fail(const char *message);
*/
import "C"
import (
	"unsafe"
)

// nyxInit initializes the Nyx agent and returns the maximum input size.
func nyxInit() int {
	return int(C.nyx_init())
}

// nyxDumpFileToHost dumps data to a file on the host filesystem.
func nyxDumpFileToHost(filename string, data []byte) {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	var cData *C.uint8_t
	if len(data) > 0 {
		cData = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}

	C.nyx_dump_file_to_host(
		cFilename,
		C.size_t(len(filename)),
		cData,
		C.size_t(len(data)),
	)
}

// nyxGetFuzzInput retrieves the next fuzz input from the Nyx hypervisor.
// Returns the actual size of the input received.
// Note: This takes a VM snapshot on the first call.
func nyxGetFuzzInput(buffer []byte, maxSize int) int {
	if len(buffer) == 0 {
		return 0
	}

	cBuffer := (*C.uint8_t)(unsafe.Pointer(&buffer[0]))
	size := C.nyx_get_fuzz_input(cBuffer, C.size_t(maxSize))
	return int(size)
}

// nyxSkip resets the coverage bitmap and the VM to the snapshot state.
// Use this to skip processing the current input.
func nyxSkip() {
	C.nyx_skip()
}

// nyxRelease resets the VM to the snapshot state.
// Use this after successfully processing an input.
func nyxRelease() {
	C.nyx_release()
}

// nyxFail indicates a crash to the fuzzer with a message.
func nyxFail(message string) {
	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))
	C.nyx_fail(cMessage)
}
