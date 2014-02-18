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
type MifareTag struct {
	tag  C.MifareTag
	dev  *nfc.Device
	info *C.nfc_iso14443a_info // may be nil
}

// Wrap a C.MifareTag and set a finalizer to automatically free the tag once it
// becomes unreachable.
func wrapTag(t C.MifareTag, d *nfc.Device, i *C.nfc_iso14443a_info) MifareTag {
	tag := MifareTag{t, d, i}
	runtime.SetFinalizer(
		tag, func(t MifareTag) {
			C.freefare_free_tag(t.tag)
			C.free(unsafe.Pointer(t.info))
		})

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

// Get the type of a MifareTag. The returned integer can be compared against the
// supplied constants to figure out what kind of tag it is.
func (t MifareTag) Type() int {
	return int(C.freefare_get_tag_type(t.tag))
}

// Get the friendly name of a MifareTag. This function wraps
// freefare_get_tag_friendly_name().
func (t MifareTag) String() string {
	cptr := C.freefare_get_tag_friendly_name(t.tag)
	return C.GoString(cptr)
}

// Get the UID of a MifareTag. The UID is a string of hexadezimal digits.
func (t MifareTag) UID() string {
	cptr := C.freefare_get_tag_uid(t.tag)
	defer C.free(unsafe.Pointer(cptr))
	return C.GoString(cptr)
}

// Get a list of the MIFARE targets near to the provided NFC initiator. If the
// list of tags cannot be generated, an error is returned. The Go wrapper takes
// care of allocating and deallocating MifareTags. No precautions are needed.
func GetTags(d *nfc.Device) ([]MifareTag, error) {
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
	var tags []MifareTag
	for *tagptr != nil {
		tags = append(tags, wrapTag(*tagptr, d, nil))

		iptr := uintptr(unsafe.Pointer(tagptr))
		iptr += unsafe.Sizeof(*tagptr)
		tagptr = (*C.MifareTag)(unsafe.Pointer(iptr))
	}

	return tags, nil
}

// Automagically allocate a MifareTag given a device and target info. The Go
// wrapper takes care of allocating and deallocating MifareTags. No precautions
// are needed. The Baud field of the info parameter is not evaluated.
func NewTag(d *nfc.Device, info *nfc.ISO14443aTarget) (MifareTag, error) {
	dd := devicePointer(d)
	if dd == nil {
		return MifareTag{}, errors.New("device closed")
	}

	// Marshall() actually returns an nfc_target, but it's first member is
	// an nfc_iso14443a_info so this is safe, although we waste a couple of
	// bytes.1
	cinfo := (*C.nfc_iso14443a_info)(unsafe.Pointer(info.Marshall()))
	ctag := C.freefare_tag_new(dd, *cinfo)
	defer C.free(unsafe.Pointer(ctag))
	if ctag == nil {
		C.free(unsafe.Pointer(ctag))
		return MifareTag{}, errors.New("Could not create tag")
	}

	return wrapTag(ctag, d, cinfo), nil
}
