package freefare

// #include <freefare.h>
import "C"
import "errors"
import "syscall"

// Wrap a Tag into a ClassicTag to access functionality available for
// Mifare Classic tags.
type ClassicTag struct {
	*Tag
}

// Mifare Classic key types
const (
	KEY_A = iota
	KEY_B
)

// Connect to a Mifare Classic tag. This causes the tag to be active.
func (t ClassicTag) Connect() error {
	r, err := C.mifare_classic_connect(t.tag)
	if r == 0 {
		return nil
	}

	// Now, figure out what exactly went wrong. mifare_classic_connect
	// helpfully sets errno to distinct values for each kind of error that
	// can occur.
	if err == nil {
		// This should actually not happen since the libfreefare
		// explicitly sets errno everywhere.
		return errors.New("unknown error")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		// nfc_initiator_select_passive_target failed.
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag already active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		// all possible errors were handled above, but anyway.
		return err
	}
}

// Disconnect from a Mifare Classic tag. This causes the tag to be inactive.
func (t ClassicTag) Disconnect() error {
	r, err := C.mifare_classic_disconnect(t.tag)
	if r == 0 {
		return nil
	}

	// Error handling as above
	if err == nil {
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag already inactive")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}

// Authenticate against a Mifare Classic tag. Use the provided constants for
// keyType.
func (t ClassicTag) Authenticate(block byte, key [6]byte, keyType int) error {
	// libfreefare does not check if keyType is actually valid so we have to
	// do that instead.
	if keyType != KEY_A && keyType != KEY_B {
		return errors.New("illegal key type")
	}

	r, err := C.mifare_classic_authenticate(
		t.tag,
		C.MifareClassicBlockNumber(block),
		(*C.uchar)(&key[0]),
		C.MifareClassicKeyType(keyType),
	)

	if r == 0 {
		return nil
	}

	// error handling as above.
	if err == nil {
		// libfreefare <= 0.4.0 does not set errno on authentication
		// failure, so assume that authentication failed when errno is
		// not set.
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}

// Read a block of data from a Mifare Classic tag. Notice that this function has
// been renamed to avoid confusion with the Read() function from io.Reader.
func (t ClassicTag) ReadBlock(block byte) ([16]byte, error) {
	cdata := C.MifareClassicBlock{}

	r, err := C.mifare_classic_read(t.tag, C.MifareClassicBlockNumber(block), &cdata)
	if r == 0 {
		bdata := [16]byte{}
		for i, d := range cdata {
			bdata[i] = byte(d)
		}

		return bdata, nil
	}

	// error handling as above
	if err == nil {
		return [16]byte{}, errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return [16]byte{}, t.dev.LastError()
	case syscall.ENXIO:
		return [16]byte{}, errors.New("tag not active")
	case syscall.ENODEV:
		return [16]byte{}, errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return [16]byte{}, errors.New("invalid block")
	case syscall.EACCES:
		return [16]byte{}, errors.New("authentication failed")
	default:
		return [16]byte{}, err
	}
}

// Write a block of data to a Mifare Classic tag. Notice that this function has
// been renamed to avoid confusion with the Write() function from io.Writer.
func (t ClassicTag) WriteBlock(block byte, data [16]byte) error {

	r, err := C.mifare_classic_write(
		t.tag,
		C.MifareClassicBlockNumber(block), (*C.uchar)(&data[0]),
	)

	if r == 0 {
		return nil
	}

	if err == nil {
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return errors.New("invalid block")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}
