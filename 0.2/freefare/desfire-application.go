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
import "unsafe"

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

// Select an application. After Connect(), the master application is selected.
// This function can be used to select a different application.
func (t DESFireTag) SelectApplication(aid DESFireAid) error {
	r, err := C.mifare_desfire_select_application(t.ctag, aid.cptr())
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}
