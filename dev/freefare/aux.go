// This package is a wrapper around the libfreefare. Error handling, some data
// structures, function names and signatures have been altered to fit the idioms
// used in Go. In order to use this wrapper, you also need the following
// package:
//
//    import "github.com/fuzxxl/nfc/0.1/nfc"
package freefare

// #include <freefare.h>
import "C"
import "github.com/fuzxxl/nfc/0.1/nfc"
import "unsafe"

// This wraps nfc.(*Device).Pointer() to return a correctly typed pointer.
func devicePointer(d *nfc.Device) *C.nfc_device {
	return (*C.nfc_device)(unsafe.Pointer(d.Pointer()))
}
