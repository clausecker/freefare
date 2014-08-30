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

/*
#include <stdlib.h>
#include <string.h>

// workaround: type is a reserved keyword, but mifare_desfire_version_info
// contains a member named type. Let's rename it to avoid trouble
#define type type_
#include <freefare.h>
#undef type
*/
import "C"
import "unsafe"

// DESFire cryptography modes. Compute the bitwise or of these constants and the
// key number to select a certain cryptography mode.
const (
	CryptoDES    = 0x00
	Crypto3k3DES = 0x40
	CryptoAES    = 0x80
)

// Mifare DESFire communication modes
const (
	Plain      = 0x00
	Maced      = 0x01
	Enciphered = 0x03

	// let the wrapper deduct the communication mode
	Default = 0xff
)

// Convert a Tag into an DESFireTag to access functionality available for
// Mifare DESFire tags. As opposed to the libfreefare itself, this wrapper does
// not provide data-level operations with explicit communication settings.
// Instead, the wrapper uses the settings stored in the DESFireTag struct or
// automatically detects them (as if the libfreefare non-ex function was called)
// if they are set to DEFAULT. When this wrapper creates a new DESFireTag,
// WriteSettings and ReadSettings are set to DEFAULT so each data access
// operation behaves like the underlying libfreefare function.
type DESFireTag struct {
	*tag

	// communication settings
	WriteSettings, ReadSettings byte
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
	err := t.Device().LastError()
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

	return Error(UnknownError)
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

// Reset t to factory defaults. For this function to work, a previous
// authentication with the card master key is required. WARNING: This function
// is irreversible and will delete all date on the card.
func (t DESFireTag) FormatPICC() error {
	r, err := C.mifare_desfire_format_picc(t.ctag)
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Version information for a Mifare DESFire tag.
type DESFireVersionInfo struct {
	Hardware, Software struct {
		VendorID                   byte
		Type, Subtype              byte
		VersionMajor, VersionMinor byte
		StorageSize                byte
		Protocol                   byte
	}

	UID                            [7]byte
	BatchNumber                    [5]byte
	ProductionWeek, ProductionYear byte
}

// Retrieve various information about t including UID. batch number, production
// date, hardware and software information.
func (t DESFireTag) Version() (DESFireVersionInfo, error) {
	var ci C.struct_mifare_desfire_version_info
	r, err := C.mifare_desfire_get_version(t.ctag, &ci)
	if r != 0 {
		return DESFireVersionInfo{}, t.TranslateError(err)
	}

	vi := DESFireVersionInfo{}

	vih := &vi.Hardware
	vih.VendorID = byte(ci.hardware.vendor_id)
	vih.Type = byte(ci.hardware.type_)
	vih.Subtype = byte(ci.hardware.subtype)
	vih.VersionMajor = byte(ci.hardware.version_major)
	vih.VersionMinor = byte(ci.hardware.version_minor)
	vih.StorageSize = byte(ci.hardware.storage_size)
	vih.Protocol = byte(ci.hardware.protocol)

	vis := &vi.Software
	vis.VendorID = byte(ci.software.vendor_id)
	vis.Type = byte(ci.software.type_)
	vis.Subtype = byte(ci.software.subtype)
	vis.VersionMajor = byte(ci.software.version_major)
	vis.VersionMinor = byte(ci.software.version_minor)
	vis.StorageSize = byte(ci.software.storage_size)
	vis.Protocol = byte(ci.software.protocol)

	for i := range vi.UID {
		vi.UID[i] = byte(ci.uid[i])
	}

	for i := range vi.BatchNumber {
		vi.BatchNumber[i] = byte(ci.batch_number[i])
	}

	vi.ProductionWeek = byte(ci.production_week)
	vi.ProductionYear = byte(ci.production_year)

	return vi, nil
}

// Get the amount of free memory on the PICC of a Mifare DESFire tag in bytes.
func (t DESFireTag) FreeMem() (uint32, error) {
	var size C.uint32_t
	r, err := C.mifare_desfire_free_mem(t.ctag, &size)
	if r != 0 {
		return 0, t.TranslateError(err)
	}

	return uint32(size), nil
}

// This function can be used to deactivate the format function or to switch
// to use a random UID.
func (t DESFireTag) SetConfiguration(disableFormat, enableRandomUID bool) error {
	// Notice that bool is a macro. the actual type is named _Bool.
	r, err := C.mifare_desfire_set_configuration(
		t.ctag, C._Bool(disableFormat), C._Bool(enableRandomUID))
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Replace the ATS bytes returned by the PICC when it is selected. This function
// performs the following extra test in order to ensure memory safety:
//
//     if len(ats) < int(ats[0]) {
//         return Error(PARAMETER_ERROR)
//     }
func (t DESFireTag) SetAts(ats []byte) error {
	// mifare_desfire_set_ats reads ats[0] bytes out of ats, so it better
	// had be that long.
	if len(ats) < int(ats[0]) {
		return Error(ParameterError)
	}

	r, err := C.mifare_desfire_set_ats(t.ctag, (*C.uint8_t)(&ats[0]))
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Get the card's UID. This function can be used to get the original UID of the
// target if the PICC is configured to return a random UID. The return value of
// CardUID() has the same format as the return value of UID(), but this function
// may fail.
func (t DESFireTag) CardUID() (string, error) {
	var cstring *C.char
	r, err := C.mifare_desfire_get_card_uid(t.ctag, &cstring)
	defer C.free(unsafe.Pointer(cstring))
	if r != 0 {
		return "", t.TranslateError(err)
	}

	return C.GoString(cstring), nil
}
