// Copyright (c) 2014, 2019, 2020, 2024 Robert Clausecker <fuzxxl@gmail.com>
//                                 2020 Nikitka Karpukhin <gray@graynk.space>
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

// #include <freefare.h>
// #include <stdlib.h>
import "C"
import "errors"
import "github.com/clausecker/nfc/v2"
import "unsafe"
import "syscall"

// This interface represents a Mifare tag of arbitrary type. You can figure out
// its type using the Type() method. To access features of a specific type of
// tag, cast it to the appropriate tag type.
//
// This interface is not designed to have other packages implement it. If you do
// so, strange things may happen.
type Tag interface {
	Connect() error
	Device() nfc.Device
	Disconnect() error
	Pointer() uintptr
	String() string
	TranslateError(error) error
	Type() int
	UID() string
}

// Generic tag structure to hold all the underlying details
type tag struct {
	ctag C.FreefareTag
	dev  nfc.Device
	info *C.nfc_target // may be nil
	*finalizee
}

// Wrap a C.MifareTag and set a finalizer to automatically free the tag once it
// becomes unreachable.
func wrapTag(t C.FreefareTag, d nfc.Device, i *C.nfc_target) Tag {
	tag := &tag{t, d, i, newFinalizee(unsafe.Pointer(t))}
	var aTag Tag
	switch tag.Type() {
	case Felica:
		panic("Felica tags are not supported")
	case Mini:
		panic("Mini tags are not supported")
	case Ultralight:
		fallthrough
	case UltralightC:
		aTag = UltralightTag{tag}
	case Classic1k:
		fallthrough
	case Classic4k:
		aTag = ClassicTag{tag}
	case DESFire:
		aTag = DESFireTag{tag, Default, Default}
	case Ntag21x:
		panic("Ntag_21x tags are not supported")
	default:
		panic("This shouldn't happen. Please report a bug.")
	}
	return aTag
}

// Mifare tag types
const (
	Felica = iota
	Mini
	Classic1k
	Classic4k
	DESFire
	Ultralight
	UltralightC
	Ntag21x
)

// Get the nfc.Devcice that was used to create t
func (t *tag) Device() nfc.Device {
	return t.dev
}

// Get the type of a Tag. The returned integer can be compared against the
// supplied constants to figure out what kind of tag it is.
func (t *tag) Type() int {
	return int(C.freefare_get_tag_type(t.ctag))
}

// Get the friendly name of a Tag. This function wraps
// freefare_get_tag_friendly_name().
func (t *tag) String() string {
	cptr := C.freefare_get_tag_friendly_name(t.ctag)
	return C.GoString(cptr)
}

// Get the UID of a Tag. The UID is a string of hexadecimal digits.
func (t *tag) UID() string {
	cptr := C.freefare_get_tag_uid(t.ctag)
	defer C.free(unsafe.Pointer(cptr))
	if cptr == nil {
		panic("C.malloc() returned nil (out of memory)")
	}

	return C.GoString(cptr)
}

// Get a list of the MIFARE targets near to the provided NFC initiator. If the
// list of tags cannot be generated, an error is returned. The Go wrapper takes
// care of allocating and deallocating Tags. No precautions are needed.
func GetTags(d nfc.Device) ([]Tag, error) {
	dd := devicePointer(d)
	if dd == nil {
		return nil, errors.New("device closed")
	}

	tagptr, err := C.freefare_get_tags(dd)
	defer C.free(unsafe.Pointer(tagptr))
	if tagptr == nil {
		if err == nil {
			return []Tag{}, d.LastError()
		}

		if err.(syscall.Errno) == syscall.ENOMEM {
			panic("C.malloc() returned nil (out of memory)")
		}

		return []Tag{}, err
	}

	// freefare_get_tags returns a nil-terminated array of pointers.
	var tags []Tag
	for *tagptr != nil {
		tags = append(tags, wrapTag(*tagptr, d, nil))

		iptr := uintptr(unsafe.Pointer(tagptr))
		iptr += unsafe.Sizeof(*tagptr)
		tagptr = (*C.FreefareTag)(unsafe.Pointer(iptr))
	}

	return tags, nil
}

// Automagically allocate a Tag given a device and target info. The Go
// wrapper takes care of allocating and deallocating Tags. No precautions
// are needed. The Baud field of the info parameter is not evaluated.
func NewTag(d nfc.Device, info *nfc.ISO14443aTarget) (Tag, error) {
	dd := devicePointer(d)
	if dd == nil {
		return nil, errors.New("device closed")
	}

	// Marshall() actually returns an nfc_target, but it's first member is
	// an nfc_iso14443a_info so this is safe, although we waste a couple of
	// bytes.1
	cinfo := (*C.nfc_target)(unsafe.Pointer(info.Marshall()))
	ctag, err := C.freefare_tag_new(dd, *cinfo)
	defer C.free(unsafe.Pointer(ctag))
	if ctag == nil {
		if err == nil {
			return nil, errors.New("could not create tag")
		}

		if err.(syscall.Errno) == syscall.ENOMEM {
			panic("C.malloc() returned nil (out of memory)")
		}
	}

	return wrapTag(ctag, d, cinfo), nil
}

// Get a pointer to the wrapped MifareTag structure. Be careful with this
// pointer: This wrapper deallocates the MifareTag once the associated Tag
// object becomes unreachable. Always keep a reference to the Tag structure when
// doing fancy stuff with the pointer!
//
// For security reasons, this function returns an uintptr. Use the package
// unsafe to do something with it.
func (t *tag) Pointer() uintptr {
	return uintptr(unsafe.Pointer(t.ctag))
}

// This wraps nfc.(*Device).Pointer() to return a correctly typed pointer.
func devicePointer(d nfc.Device) *C.nfc_device {
	return (*C.nfc_device)(unsafe.Pointer(d.Pointer()))
}
