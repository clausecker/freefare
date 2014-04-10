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

// This package is a wrapper around the libfreefare. Error handling, some data
// structures, function names and signatures have been altered to fit the idioms
// used in Go. In order to use this wrapper, you also need the following
// package:
//
//    import "github.com/fuzxxl/nfc/1.0/nfc"
package freefare

// #include <freefare.h>
import "C"
import "github.com/fuzxxl/nfc/1.0/nfc"
import "unsafe"

// This wraps nfc.(*Device).Pointer() to return a correctly typed pointer.
func devicePointer(d nfc.Device) *C.nfc_device {
	return (*C.nfc_device)(unsafe.Pointer(d.Pointer()))
}
