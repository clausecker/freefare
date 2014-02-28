package freefare

// #include <freefare.h>
import "C"
import "errors"
import "syscall"

// Wrap a Tag into an UltralightTag to access functionality available for
// Mifare Ultralight tags.
type UltralightTag struct {
	*Tag
}

// Connect to a Mifare Ultralight Tag. This causes the tag to be active.
func (t UltralightTag) Connect() error {
	r, err := C.mifare_ultralight_connect(t.tag)
	if r == 0 {
		return nil
	}

	// Now, figure out what exactly went wrong. mifare_ultralight_connect
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
		return errors.New("tag is not a Mifare Ultralight tag")
	default:
		// all possible errors were handled above, but anyway.
		return err
	}
}

// Disconnect from a Mifare Ultralight Tag. This causes the tag to be inactive.
func (t UltralightTag) Disconnect() error {
	r, err := C.mifare_ultralight_disconnect(t.tag)
	if r == 0 {
		return nil
	}

	// Error handling as above
	if err == nil {
		return errors.New("unknown error")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag already inactive")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Ultralight tag")
	default:
		return err
	}
}

// Read one page of data from a Mifare Ultralight tag. page denotes the page
// number you want to read. Notice that page should not be larger than 16 in
// case of an Ultralight tag and not larger than 44 in case of an Ultralight C
// tag.
//
// Please notice that this function has been renamed to avoid confusion with the
// Read() function from io.Reader.
func (t UltralightTag) ReadPage(page byte) ([4]byte, error) {
	var cdata C.MifareUltralightPage

	r, err := C.mifare_ultralight_read(
		t.tag,
		C.MifareUltralightPageNumber(page),
		&cdata,
	)

	if r == 0 {
		var data [4]byte
		for i, d := range cdata {
			data[i] = byte(d)
		}

		return [4]byte{}, nil
	}

	// Error handling as above
	if err == nil {
		return [4]byte{}, errors.New("unknown error")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return [4]byte{}, t.dev.LastError()
	case syscall.ENXIO:
		return [4]byte{}, errors.New("tag not active")
	case syscall.ENODEV:
		return [4]byte{}, errors.New("tag is not a Mifare Ultralight tag")
	case syscall.EINVAL:
		return [4]byte{}, errors.New("invalid page")
	default:
		return [4]byte{}, err
	}
}

// Write one page of data from a Mifare Ultralight tag. page denotes the page
// number you want to write. Notice that page should not be larger than 16 in
// case of an Ultralight tag and not larger than 48 in case of an Ultralight C
// tag.
//
// Please notice that this function has been renamed to avoid confusion with the
// Write() function from io.Writer.
func (t UltralightTag) WritePage(page byte, data [4]byte) error {
	var cdata C.MifareUltralightPage
	for i, d := range data {
		cdata[i] = C.uchar(d)
	}

	r, err := C.mifare_ultralight_write(
		t.tag,
		C.MifareUltralightPageNumber(page),
		&cdata[0],
	)

	if r == 0 {
		return nil
	}

	// Error handling as above
	if err == nil {
		return errors.New("unknown error")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Ultralight tag")
	case syscall.EINVAL:
		return errors.New("invalid page")
	default:
		return err
	}
}

// Authentificate to a Mifare Ultralight tag. Note that this only works with
// MifareUltralightC tags.
func (t UltralightTag) Authenticate(key DESFireKey) error {
	r, err := C.mifare_ultralightc_authenticate(t.tag, key.key)
	if r == 0 {
		return nil
	}

	// error handling as above.
	if err == nil {

		// error handling is inconsistentent here: the libfreefare does
		// not set errno (!) when the authentication failes, even though
		// there are several perfectly valid errnos to use for this
		// case, such as EACCES (best choice), ECONNREFUSED, or EPROTO.
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare UltralightC tag")
	default:
		return err
	}
}
