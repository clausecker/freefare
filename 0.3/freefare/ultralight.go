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

		return [4]byte{}, nil
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
