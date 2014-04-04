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
// #include <stdlib.h>
import "C"
import "unsafe"

// DESFire file types
const (
	STANDARD_DATA_FILE = iota
	BACKUP_DATA_FILE
	VALUE_FILE_WITH_BACKUP
	LINEAR_RECORD_FILE_WITH_BACKUP
	CYCLIC_RECORD_FILE_WITH_BACKUP
)

// DESFire cryptography modes. Compute the bitwise or of these constants and the
// key number to select a certain cryptography mode.
const (
	CRYPTO_DES    = 0x00
	CRYPTO_3K3DES = 0x40
	CRYPTO_AES    = 0x80
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

// Return the key settings and maximum number of keys for the selected
// application.
func (t DESFireTag) KeySettings() (settings, maxKeys byte, err error) {
	var s, mk C.uint8_t
	r, err := C.mifare_desfire_get_key_settings(t.ctag, &s, &mk)
	if r != 0 {
		return 0, 0, t.TranslateError(err)
	}

	settings = byte(s)
	maxKeys = byte(mk)
	err = nil
	return
}

// Change the key keyNo from oldKey to newKey. Depending on the application
// settings, a previous authentication with the same key or another key may be
// required.
func (t DESFireTag) ChangeKey(keyNo byte, newKey, oldKey DESFireKey) error {
	r, err := C.mifare_desfire_change_key(t.ctag, C.uint8_t(keyNo), newKey.key, oldKey.key)
	if r == 0 {
		return nil
	}

	return t.TranslateError(err)
}

// Retrieve the version of the key keyNo for the selected application.
func (t DESFireTag) KeyVersion(keyNo byte) (byte, error) {
	var version C.uint8_t
	r, err := C.mifare_desfire_get_key_version(t.ctag, C.uint8_t(keyNo), &version)
	if r != 0 {
		return 0, t.TranslateError(err)
	}

	return byte(version), nil
}

// Create a new application with AID aid, settings and keyNo authentication
// keys. Authentication keys are set to 0 after creation. This wrapper does not
// wrap the functions mifare_desfire_create_application_3k3des() and
// mifare_desfire_create_application_aes(). Or keyNo with the constants
// CRYPTO_3K3DES and CRYPTO_AES instead.
func (t DESFireTag) CreateApplication(aid DESFireAid, settings, keyNo byte) error {
	r, err := C.mifare_desfire_create_application(
		t.ctag, aid.cptr(), C.uint8_t(settings), C.uint8_t(keyNo))
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Create a new application with AID aid, settings, keyNo authentication keys,
// and, if wantIsoFileIdentifiers is true, an ISO file ID and an optional file
// name isoFileName. This wrapper does not wrap the functions
// mifare_desfire_create_application_3k3des_iso and
// mifare_desfire_create_application_aes_iso(). Or keyNo with the constants
// CRYPTO_3K3DES and CRYPTO_AES instead.
func (t DESFireTag) CreateApplicationIso(
	aid DESFireAid,
	settings byte,
	keyNo byte,
	wantIsoFileIdentifiers bool,
	isoFileId uint16,
	isoFileName []byte,
) error {
	wifi := C.int(0)
	if wantIsoFileIdentifiers {
		wifi = 1
	}

	r, err := C.mifare_desfire_create_application_iso(
		t.ctag,
		aid.cptr(),
		C.uint8_t(settings),
		C.uint8_t(keyNo),
		wifi,
		C.uint16_t(isoFileId),
		(*C.uint8_t)(&isoFileName[0]),
		C.size_t(len(isoFileName)))
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Delete the application identified by aid
func (t DESFireTag) DeleteApplication(aid DESFireAid) error {
	r, err := C.mifare_desfire_delete_application(t.ctag, aid.cptr())
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

//mifare_desfire_get_application_ids (MifareTag tag, MifareDESFireAID *aids[], size_t *count);

// Return a list of all applications of the card
func (t DESFireTag) ApplicationIds() ([]DESFireAid, error) {
	var count C.size_t
	var caids *C.MifareDESFireAID
	r, err := C.mifare_desfire_get_application_ids(t.ctag, &caids, &count)
	if r != 0 {
		return nil, t.TranslateError(err)
	}

	aids := make([]DESFireAid, int(count))
	aidsptr := uintptr(unsafe.Pointer(caids))
	for i := range aids {
		// Assume that a C.MifareDESFireAID is a *[3]C.uint8_t
		aidptr := (*DESFireAid)(unsafe.Pointer(aidsptr + uintptr(i)*unsafe.Sizeof(*caids)))
		aids[i] = *aidptr
	}

	C.mifare_desfire_free_application_ids(caids)
	return aids, nil
}

// A Mifare DESFire directory file
type DESFireDF struct {
	DESFireAid
	Fid  uint16 // file ID
	Name []byte // no longer than 16 bytes
}

// Retrieve a list of directory file (df) names
func (t DESFireTag) DFNames() ([]DESFireDF, error) {
	var count C.size_t
	var cdfs *C.MifareDESFireDF
	r, err := C.mifare_desfire_get_df_names(t.ctag, &cdfs, &count)
	if r != 0 {
		return nil, t.TranslateError(err)
	}

	dfs := make([]DESFireDF, int(count))
	dfsptr := uintptr(unsafe.Pointer(cdfs))
	for i := range dfs {
		dfptr := (*C.MifareDESFireDF)(unsafe.Pointer(dfsptr + uintptr(i)*unsafe.Sizeof(*cdfs)))
		dfs[i] = DESFireDF{
			NewDESFireAid(uint32(dfptr.aid)),
			uint16(dfptr.fid),
			C.GoBytes(unsafe.Pointer(&dfptr.df_name[0]), C.int(dfptr.df_name_len)),
		}
	}

	C.free(unsafe.Pointer(dfsptr))
	return dfs, nil
}

// Select an application. After Connect(), the master application is selected.
// This function can be used to select a different application.
func (t DESFireTag) SelectApplication(aid DESFireAid) error {
	r, err := C.mifare_desfire_select_application(t.ctag, aid.cptr())
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}
