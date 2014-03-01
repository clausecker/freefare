package freefare

// #include <stdlib.h>
import "C"
import "runtime"
import "unsafe"

// A finalizee contains a pointer to malloc'ed data and is usually connected to
// a finalizer that free's ptr once this struct becomes unreachable. This can be
// used to make it possible to treat malloc'ed structs like structs that are
// allocated by the Go runtime.
//
// See http://code.google.com/p/go/issues/detail?id=7358 for why an extra
// struct is neccessary. Please notice that copying finalizees may impair memory
// safety.
type finalizee struct {
	ptr unsafe.Pointer
}

// Wrap a pointer into a finalizee and register a finalizer to free the pointer
// once the object becomes unreachable.
func newFinalizee(ptr unsafe.Pointer) *finalizee {
	f := &finalizee{ptr}
	runtime.SetFinalizer(f, func(f *finalizee) {
		C.free(f.ptr)
	})

	return f
}
