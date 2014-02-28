package freefare

// #cgo LDFLAGS: -lfreefare
// #include <freefare.h>
// #include <stdlib.h>
import "C"
import "errors"
import "github.com/fuzxxl/nfc/dev/nfc"
import "runtime"
import "unsafe"

// This struct represents a Mifare tag of arbitrary type. You can figure out its
// type with the Type() method. To access features of a specific type of tag,
// wrap it into one of the other tag types.
type Tag struct {
	tag  C.MifareTag
	dev  *nfc.Device
	info *C.nfc_iso14443a_info // may be nil

	// The singleton pointer makes sure that the instance of a Tag that
	// carries the finalizer is referenced as long as there is any copy of
	// it is around. This makes sure that the finalizer is not run to early.
	singleton *Tag
}

// Wrap a C.MifareTag and set a finalizer to automatically free the tag once it
// becomes unreachable.
func wrapTag(t C.MifareTag, d *nfc.Device, i *C.nfc_iso14443a_info) *Tag {
	tag := &Tag{t, d, i, nil}
	runtime.SetFinalizer(
		tag, func(t Tag) {
			C.freefare_free_tag(t.tag)
			C.free(unsafe.Pointer(t.info))
		})

	tag.singleton = tag

	return tag
}

// Mifare tag types
const (
	ULTRALIGHT = iota
	ULTRALIGHT_C
	CLASSIC_1K
	CLASSIC_4k
	DESFIRE
)

// Get the type of a Tag. The returned integer can be compared against the
// supplied constants to figure out what kind of tag it is.
func (t *Tag) Type() int {
	return int(C.freefare_get_tag_type(t.tag))
}

// Get the friendly name of a Tag. This function wraps
// freefare_get_tag_friendly_name().
func (t *Tag) String() string {
	cptr := C.freefare_get_tag_friendly_name(t.tag)
	return C.GoString(cptr)
}

// Get the UID of a Tag. The UID is a string of hexadecimal digits.
func (t *Tag) UID() string {
	cptr := C.freefare_get_tag_uid(t.tag)
	defer C.free(unsafe.Pointer(cptr))
	return C.GoString(cptr)
}

// Get a list of the MIFARE targets near to the provided NFC initiator. If the
// list of tags cannot be generated, an error is returned. The Go wrapper takes
// care of allocating and deallocating Tags. No precautions are needed.
func GetTags(d *nfc.Device) ([]*Tag, error) {
	dd := devicePointer(d)
	if dd == nil {
		return nil, errors.New("device closed")
	}

	tagptr := C.freefare_get_tags(dd)
	defer C.free(unsafe.Pointer(tagptr))
	if tagptr == nil {
		return nil, errors.New("cannot generate list of tags")
	}

	// freefare_get_tags returns a nil-terminated array of pointers.
	var tags []*Tag
	for *tagptr != nil {
		tags = append(tags, wrapTag(*tagptr, d, nil))

		iptr := uintptr(unsafe.Pointer(tagptr))
		iptr += unsafe.Sizeof(*tagptr)
		tagptr = (*C.MifareTag)(unsafe.Pointer(iptr))
	}

	return tags, nil
}

// Automagically allocate a Tag given a device and target info. The Go
// wrapper takes care of allocating and deallocating Tags. No precautions
// are needed. The Baud field of the info parameter is not evaluated.
func NewTag(d *nfc.Device, info *nfc.ISO14443aTarget) (*Tag, error) {
	dd := devicePointer(d)
	if dd == nil {
		return nil, errors.New("device closed")
	}

	// Marshall() actually returns an nfc_target, but it's first member is
	// an nfc_iso14443a_info so this is safe, although we waste a couple of
	// bytes.1
	cinfo := (*C.nfc_iso14443a_info)(unsafe.Pointer(info.Marshall()))
	ctag := C.freefare_tag_new(dd, *cinfo)
	defer C.free(unsafe.Pointer(ctag))
	if ctag == nil {
		C.free(unsafe.Pointer(ctag))
		return nil, errors.New("Could not create tag")
	}

	return wrapTag(ctag, d, cinfo), nil
}
