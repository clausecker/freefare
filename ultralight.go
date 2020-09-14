// Copyright (c) 2014, 2020 Robert Clausecker <fuzxxl@gmail.com>
//                     2020 Nikitka Karpukhin <gray@graynk.space>
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

// Convert a Tag into an UltralightTag to access functionality available for
// Mifare Ultralight tags.
type UltralightTag struct {
	*tag
}

// Connect to a Mifare Ultralight tag. This causes the tag to be active.
func (t UltralightTag) Connect() error {
	r, err := C.mifare_ultralight_connect(t.ctag)
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Disconnect from a Mifare Ultralight tag. This causes the tag to be inactive.
func (t UltralightTag) Disconnect() error {
	r, err := C.mifare_ultralight_disconnect(t.ctag)
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
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
		t.ctag,
		C.MifareUltralightPageNumber(page),
		&cdata,
	)

	if r == 0 {
		var data [4]byte
		for i, d := range cdata {
			data[i] = byte(d)
		}

		return data, nil
	}

	return [4]byte{}, t.TranslateError(err)
}

// Write one page of data from a Mifare Ultralight tag. page denotes the page
// number you want to write. Notice that page should not be larger than 16 in
// case of an Ultralight tag and not larger than 48 in case of an Ultralight C
// tag.
//
// Please notice that this function has been renamed to avoid confusion with the
// Write() function from io.Writer.
func (t UltralightTag) WritePage(page byte, data [4]byte) error {
	r, err := C.mifare_ultralight_write(
		t.ctag,
		C.MifareUltralightPageNumber(page),
		(*C.uchar)(&data[0]),
	)

	if r == 0 {
		return nil
	}

	return t.TranslateError(err)
}

// Authentificate to a Mifare Ultralight tag. Note that this only works with
// MifareUltralightC tags.
func (t UltralightTag) Authenticate(key DESFireKey) error {
	r, err := C.mifare_ultralightc_authenticate(t.ctag, key.key)
	if r == 0 {
		return nil
	}
	return t.TranslateError(err)
}

// Set the provided authentication key. Note that this only works with
// MifareUltralightC tags. It _should_ work only after authentication,
// but for some reason the opposite is true: it only works without it.
func (t UltralightTag) SetKey(key DESFireKey) error {
	r, err := C.mifare_ultralightc_set_key(t.ctag, key.key)
	if r == 0 {
		return nil
	}

	return t.TranslateError(err)
}

// Allocate a new key deriver object which can be used to generate
// diversified keys from masterKey in accordance with AN10922.
// The non-AN10922 compliant operation mode provided for compatibility
// with old versions of the libfreefare is not supported.
func (t UltralightTag) NewAn10922(masterKey DESFireKey, keyType MifareKeyType) (kd MifareKeyDeriver, err error) {
	deriver, err := C.mifare_key_deriver_new_an10922(masterKey.key, C.MifareKeyType(keyType), 0)
	if deriver == nil {
		err = t.TranslateError(err)
		return
	}

	kd.tag = t.tag
	kd.deriver = deriver
	kd.finalizee = newFinalizee(unsafe.Pointer(deriver))

	return
}

// Helper method that takes the master key and derives a new key based on tag UID
func (t UltralightTag) Diversify(masterKey DESFireKey) (*DESFireKey, error) {
	deriver, err := t.NewAn10922(masterKey, MIFARE_KEY_2K3DES)
	if err != nil {
		return nil, err
	}

	err = deriver.Begin()
	if err != nil {
		return nil, err
	}

	err = deriver.UpdateUID(nil)
	if err != nil {
		return nil, err
	}

	derivedKey, err := deriver.End()
	if err != nil {
		return nil, err
	}

	return derivedKey, nil
}

// Helper function to change the authentication keys on the tag
func (t UltralightTag) SwapKeys(oldKey, newKey DESFireKey) error {
	err := t.Authenticate(oldKey)

	if err != nil {
		t.Disconnect()
		t.Connect()
	}

	return t.SetKey(newKey)
}
