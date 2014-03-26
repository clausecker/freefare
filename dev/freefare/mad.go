package freefare

// #include <stdlib.h>
// #include <string.h>
// #include <freefare.h>
import "C"
import "unsafe"
import "syscall"

// Wraps a MadAid (MAD application identifier). Use the provided accessor
// functions to operate on objects of this type.
type MadAid struct {
	aid C.MadAid
}

// Make a new MadAid
func NewMadAid(applicationCode, functionClusterCode byte) MadAid {
	return MadAid{C.MadAid{
		application_code:      C.uint8_t(applicationCode),
		function_cluster_code: C.uint8_t(functionClusterCode),
	}}
}

// Predefined MadAid values
var (
	// AID - Administration codes
	FreeAid          = NewMadAid(0x00, 0x00)
	DefectAid        = NewMadAid(0x01, 0x00)
	ReservedAid      = NewMadAid(0x02, 0x00)
	CardHolderAid    = NewMadAid(0x04, 0x00)
	NotApplicableAid = NewMadAid(0x05, 0x00)

	// NFC Forum AID
	MadNFCForumAid = NewMadAid(0x03, 0xe1)
)

// Read the application_code field
func (m MadAid) ApplicationCode() byte {
	return byte(m.aid.application_code)
}

// Read the function_cluster_code field
func (m MadAid) FunctionClusterCode() byte {
	return byte(m.aid.function_cluster_code)
}

// Read all parameters from a MadAid
func (m MadAid) Content() (applicationCode, functionClusterCode byte) {
	return m.ApplicationCode(), m.FunctionClusterCode()
}

// A Mifare application directory. This struct wraps Mad. The wrapper takes
// care of automatic deallocation.
type Mad struct {
	m C.Mad
	*finalizee
}

// Wrap a C.Mad and set a finalizer to automatically free the mad once it
// becomes unreachable.
func wrapMad(m C.Mad) *Mad {
	mad := &Mad{m, newFinalizee(unsafe.Pointer(m))}
	return mad
}

// Create a new MAD. The Go wrapper automatically takes care of allocation and
// deallocation.
func NewMad(version byte) *Mad {
	m := C.mad_new(C.uint8_t(version))
	if m != nil {
		return wrapMad(m)
	}

	// Out of memory is not a usual error condition. The Go runtime panics
	// if memory allocation fails, so we follow suit.
	panic("C.malloc() returned nil (out of memory)")
}

// Read a MAD from a Mifare Classic tag. This function wraps mad_read().
func (t ClassicTag) ReadMad() (*Mad, error) {
	m, err := C.mad_read(t.tag)
	if m != nil {
		return wrapMad(m), nil
	}

	return nil, t.resolveError(err)
}

// Write a MAD to a Mifare tag using the provided Key-B keys.
func (t ClassicTag) WriteMad(m *Mad, sector00keyB, sector10keyB [6]byte) error {
	r, err := C.mad_write(
		t.tag,
		m.m,
		(*C.uchar)(&sector00keyB[0]),
		(*C.uchar)(&sector10keyB[0]),
	)

	if r == 0 {
		return nil
	}

	return t.resolveError(err)
}

// Get MAD version. This function wraps mad_get_version().
func (m *Mad) Version() int {
	return int(C.mad_get_version(m.m))
}

// Set MAD version. This function wraps mad_set_version().
func (m *Mad) SetVersion(version byte) {
	C.mad_set_version(m.m, C.uint8_t(version))
}

// Get the number of the publisher sector
func (m *Mad) PublisherSector() byte {
	return byte(C.mad_get_card_publisher_sector(m.m))
}

// Set the MAD card publisher sector number. This returns an error if the sector
// number you provided is invalid.
func (m *Mad) SetPublisherSector(cps byte) error {
	r, err := C.mad_set_card_publisher_sector(m.m, C.MifareClassicSectorNumber(cps))
	if r == 0 {
		return nil
	}

	if err == nil {
		return Error(UNKNOWN_ERROR)
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EINVAL:
		return Error(PARAMETER_ERROR)
	default:
		return err
	}
}

// Get the provided sector's application identifier. An error occurs if sector
// is invalid.
func (m *Mad) Aid(sector byte) (MadAid, error) {
	aid := MadAid{}
	r, err := C.mad_get_aid(m.m, C.MifareClassicSectorNumber(sector), &aid.aid)
	if r == 0 {
		return aid, nil
	}

	// this shouldn't happen, but libfreefare might have bugs
	if err == nil {
		return aid, Error(UNKNOWN_ERROR)
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EINVAL:
		return aid, Error(PARAMETER_ERROR)
	default:
		return aid, err
	}
}

// Set the provided sector's application identifier. An error occurs if the
// sector is invalid.
func (m *Mad) SetAid(sector byte, aid MadAid) error {
	r, err := C.mad_set_aid(m.m, C.MifareClassicSectorNumber(sector), aid.aid)
	if r == 0 {
		return nil
	}

	if err == nil {
		return Error(UNKNOWN_ERROR)
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EINVAL:
		return Error(PARAMETER_ERROR)
	default:
		return err
	}
}

// Tell if a certain sector has been reserved. This wraps mad_sector_reserved().
func (m *Mad) Reserved(sector byte) bool {
	return bool(C.mad_sector_reserved(C.MifareClassicSectorNumber(sector)))
}

// Allocate a new application into a MAD. This function returns a slice of
// newly allocated sectors. This function returns nil if the application already
// exists. This function wraps mifare_application_alloc().
func (m *Mad) AllocApplication(aid MadAid, size uint) []byte {
	r, err := C.mifare_application_alloc(m.m, aid.aid, C.size_t(size))
	defer C.free(unsafe.Pointer(r))
	if r != nil {
		return C.GoBytes(unsafe.Pointer(r), C.int(C.strlen((*C.char)(unsafe.Pointer(r)))))
	}

	// no error occurred (hopefully). Let's expect the application already
	// exists
	if err == nil {
		return nil
	}

	// the only error that might happen is out-of-memory.
	panic("C.malloc() returned nil (out of memory)")
}

// Remove an application from a MAD. If the application does not exist, this
// function is a NOP. This function wraps mifare_application_free().
func (m *Mad) FreeApplication(aid MadAid) {
	// mifare_application_free() does not check if the return value of
	// mifare_application_find() is NULL and chooses to crash instead. As
	// crashing is considered bad style in Go, we try to work around this.
	r, err := C.mifare_application_find(m.m, aid.aid)
	defer C.free(unsafe.Pointer(r))
	if r == nil && err == nil {
		return // application not found
	}

	if r == nil && err != nil {
		// no other error can occur
		panic("C.malloc() returned nil (out of memory)")
	}

	// let's hope it works this time.
	_, err = C.mifare_application_free(m.m, aid.aid)
	if err != nil {
		panic("C.malloc() returned nil (out of memory)")
	}
}

// Get all sector numbers of an application from the provided MAD. This function
// returns nil if the application could not be found. This function
// mifare_application_find().
func (m *Mad) FindApplication(aid MadAid) []byte {
	r, err := C.mifare_application_find(m.m, aid.aid)
	defer C.free(unsafe.Pointer(r))
	if r == nil && err == nil {
		return nil // application not found
	}

	if r == nil && err != nil {
		// no other error can occur
		panic("C.malloc() returned nil (out of memory)")
	}

	return C.GoBytes(unsafe.Pointer(r), C.int(C.strlen((*C.char)(unsafe.Pointer(r)))))
}

// Read the provided application sectors from a Mifare Classic tag. This
// function returns the number of sectors read or a negative number and an
// error. This function wraps mifare_application_read().
func (t ClassicTag) ReadApplication(m *Mad, aid MadAid, buf []byte, key [6]byte, keyType int) (int, error) {
	r, err := C.mifare_application_read(
		t.tag, m.m, aid.aid,
		unsafe.Pointer(&buf[0]),
		C.size_t(len(buf)),
		(*C.uchar)(&key[0]),
		C.MifareClassicKeyType(keyType),
	)

	if r >= 0 {
		return int(r), nil
	}

	return -1, t.resolveError(err)
}

// Write the provided application sector to a Mifare Classic tag. This function
// returns the number of bytes written or a negative number and an error. This
// function wraps mifare_application_write().
func (t ClassicTag) WriteApplication(m *Mad, aid MadAid, buf []byte, key [6]byte, keyType int) (int, error) {
	r, err := C.mifare_application_write(
		t.tag, m.m, aid.aid,
		unsafe.Pointer(&buf[0]),
		C.size_t(len(buf)),
		(*C.uchar)(&key[0]),
		C.MifareClassicKeyType(keyType),
	)

	if r >= 0 {
		return int(r), nil
	}

	return -1, t.resolveError(err)
}
