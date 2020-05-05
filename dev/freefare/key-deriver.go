// Copyright (c) 2020 Nikitka Karpukhin <gray@graynk.space>
//                    Robert Clausecker <fuzxxl@gmail.com>
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

type MifareKeyType int

// Key types for use with MifareKeyDeriver
const (
	MIFARE_KEY_DES MifareKeyType = iota
	MIFARE_KEY_2K3DES
	MIFARE_KEY_3K3DES
	MIFARE_KEY_AES128
)

// Opaque state of an AN10922 key derivation process.
type MifareKeyDeriver struct {
	tag     *tag
	deriver C.MifareKeyDeriver
	*finalizee
}

// Start the derivation of a new diversified key.
func (d *MifareKeyDeriver) Begin() error {
	r, err := C.mifare_key_deriver_begin(d.deriver)
	if r != 0 {
		return d.tag.TranslateError(err)
	}

	return nil
}

// Specify a UID to diversify the key from the master key.
// If t is nil, the tag used to create this MifareKeyDeriver
// is used instead.
func (d *MifareKeyDeriver) UpdateUID(t Tag) error {
	tp := d.tag.ctag

	if t != nil {
		tp = C.FreefareTag(unsafe.Pointer(t.Pointer()))
	}

	r, err := C.mifare_key_deriver_update_uid(d.deriver, tp)
	if r != 0 {
		return d.tag.TranslateError(err)
	}

	return nil
}

// Specify an AID to diversify the key from the master key.
func (d *MifareKeyDeriver) UpdateAID(aid DESFireAid) error {
	r, err := C.mifare_key_deriver_update_aid(d.deriver, aid.cptr())
	if r != 0 {
		return d.tag.TranslateError(err)
	}

	return nil
}

// Specify data to diversify the key from the master key.
func (d *MifareKeyDeriver) UpdateData(data []byte) error {
	r, err := C.mifare_key_deriver_update_data(d.deriver, (*C.uchar)(&data[0]), C.size_t(len(data)))
	if r != 0 {
		return d.tag.TranslateError(err)
	}

	return nil
}

// Specify a string to diversify the key from the master key.
func (d *MifareKeyDeriver) UpdateString(str string) error {
	return d.UpdateData([]byte(str))
}

// Mark the end of a derivation and return the new diversified key.
func (d *MifareKeyDeriver) End() (*DESFireKey, error) {
	key, err := C.mifare_key_deriver_end(d.deriver)
	if key == nil {
		return nil, d.tag.TranslateError(err)
	}

	return wrapDESFireKey(key), nil
}

// Mark the end of a derivation and store the new diversified key
// to key.  The length of the key is returned.  If this length is
// longer than len(key), no bytes were written to key and a
// LengthError is returned.
func (d *MifareKeyDeriver) EndRaw(key []byte) (int, error) {
	r, err := C.mifare_key_deriver_end_raw(d.deriver, (*C.uchar)(&key[0]), C.size_t(len(key)))
	if r == -1 {
		return int(r), d.tag.TranslateError(err)
	} else if int(r) > len(key) {
		return int(r), Error(LengthError)
	}

	return int(r), nil
}
