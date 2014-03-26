package freefare

// #include <freefare.h>
import "C"

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

// Get last PCD error. This function wraps mifare_desfire_last_pcd_error().
func (t DESFireTag) LastPCDError() byte {
	return byte(C.mifare_desfire_last_pcd_error(t.tag))
}

// Get last PICC error. This function wraps mifare_desfire_last_picc_error().
func (t DESFireTag) LastPICCError() byte {
	return byte(C.mifare_desfire_last_picc_error(t.tag))
}

// Figure out what kind of error is hidden behind an EIO. This function largely
// replicates the behavior of freefare_strerror().
func (t DESFireTag) resolveEIO() error {
	err := t.dev.LastError()
	if err != nil {
		return err
	}

	enr := Error(t.LastPCDError())
	if enr != OPERATION_OK {
		return enr
	}

	enr = Error(t.LastPICCError())
	if enr != OPERATION_OK {
		return enr
	}

	return Error(UNKNOWN_ERROR)
}

// Connect to a Mifare DESFire tag. This causes the tag to be active.
func (t DESFireTag) Connect() error {
	r, err := C.mifare_desfire_connect(t.tag)
	if r != 0 {
		return t.resolveError(err)
	}

	return nil
}

// Disconnect from a Mifare DESFire tag. This causes the tag to be inactive.
func (t DESFireTag) Disconnect() error {
	r, err := C.mifare_desfire_disconnect(t.tag)
	if r != 0 {
		return t.resolveError(err)
	}

	return nil
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

	return t.resolveError(err)
}
