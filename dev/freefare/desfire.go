package freefare

// #include <freefare.h>
import "C"
import "errors"
import "syscall"

// DESFire file types
const (
	STANDARD_DATA_FILE = iota
	BACKUP_DATA_FILE
	VALUE_FILE_WITH_BACKUP
	LINEAR_RECORD_FILE_WITH_BACKUP
	CYCLIC_RECORD_FILE_WITH_BACKUP
)

// Wrap a Tag into an DESFireTag to access functionality available for
// Mifare DESFire tags.
type DESFireTag struct {
	*Tag
}

// Connect to a Mifare DESFire tag. This causes the tag to be active.
func (t DESFireTag) Connect() error {
	return t.genericConnect(func(t C.MifareTag) (C.int, error) {
		r, err := C.mifare_desfire_connect(t)
		return r, err
	})
}

// Disconnect from a Mifare DESFire tag. This causes the tag to be inactive.
func (t DESFireTag) Disconnect() error {
	return t.genericDisconnect(func(t C.MifareTag) (C.int, error) {
		r, err := C.mifare_desfire_disconnect(t)
		return r, err
	})
}

// Authenticate to a Mifare DESFire tag. Notice that this wrapper does not
// provide wrappers for the mifare_desfire_authenticate_iso() and
// mifare_desfire_authenticate_aes() functions as the key type can be deducted
// from the key.
func (t DESFireTag) Authenticate(keyNo byte, key DESFireKey) error {
	r, err := C.mifare_desfire_authenticate(t.tag, C.uint8_t(keyNo), key.key)
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
		return errors.New("tag is not a Mifare UltralightC tag")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}
