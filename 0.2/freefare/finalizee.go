// Copyright (c) 2014, Robert Clausecker <fuzxxl@gmail.com>
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>

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
