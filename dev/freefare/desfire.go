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

// Convert a Tag into an DESFireTag to access functionality available for
// Mifare DESFire tags.
type DESFireTag struct {
	*tag
}

// Get last PCD error. This function wraps mifare_desfire_last_pcd_error(). If
// no error has occured, this function returns nil.
func (t DESFireTag) LastPCDError() error {
	err := Error(C.mifare_desfire_last_pcd_error(t.ctag))
	if err == 0 {
		return nil
	} else {
		return err
	}
}

// Get last PICC error. This function wraps mifare_desfire_last_picc_error(). If
// no error has occured, this function returns nil.
func (t DESFireTag) LastPICCError() error {
	err := Error(C.mifare_desfire_last_picc_error(t.ctag))
	if err == 0 {
		return nil
	} else {
		return err
	}
}

// Figure out what kind of error is hidden behind an EIO. This function largely
// replicates the behavior of freefare_strerror().
func (t DESFireTag) resolveEIO() error {
	err := t.dev.LastError()
	if err != nil {
		return err
	}

	err = t.LastPCDError()
	if err != nil {
		return err
	}

	err = t.LastPICCError()
	if err != nil {
		return err
	}

	return Error(UNKNOWN_ERROR)
}

// Connect to a Mifare DESFire tag. This causes the tag to be active.
func (t DESFireTag) Connect() error {
	r, err := C.mifare_desfire_connect(t.ctag)
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Disconnect from a Mifare DESFire tag. This causes the tag to be inactive.
func (t DESFireTag) Disconnect() error {
	r, err := C.mifare_desfire_disconnect(t.ctag)
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Authenticate to a Mifare DESFire tag. Notice that this wrapper does not
// provide wrappers for the mifare_desfire_authenticate_iso() and
// mifare_desfire_authenticate_aes() functions as the key type can be deducted
// from the key.
func (t DESFireTag) Authenticate(keyNo byte, key DESFireKey) error {
	r, err := C.mifare_desfire_authenticate(t.ctag, C.uint8_t(keyNo), key.key)
	if r == 0 {
		return nil
	}

	return t.TranslateError(err)
}

// Change the selected application settings to s. The application number of keys
// cannot be changed after the application has been created.
func (t DESFireTag) ChangeKeySettings(s byte) error {
	r, err := C.mifare_desfire_change_key_settings(t.ctag, C.uint8_t(s))
	if r == 0 {
		return nil
	}

	return t.TranslateError(err)
}
