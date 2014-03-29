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

// Convert a Tag into a ClassicTag to access functionality available for
// Mifare Classic tags.
type ClassicTag struct {
	*tag
}

// Mifare Classic key types
const (
	KEY_A = iota
	KEY_B
)

// Connect to a Mifare Classic tag. This causes the tag to be active.
func (t ClassicTag) Connect() error {
	r, err := C.mifare_classic_connect(t.ctag)
	if r != 0 {
		return t.resolveError(err)
	}

	return nil
}

// Disconnect from a Mifare Classic tag. This causes the tag to be inactive.
func (t ClassicTag) Disconnect() error {
	r, err := C.mifare_classic_disconnect(t.ctag)
	if r != 0 {
		return t.resolveError(err)
	}

	return nil
}

// Authenticate against a Mifare Classic tag. Use the provided constants for
// keyType.
func (t ClassicTag) Authenticate(block byte, key [6]byte, keyType int) error {
	// libfreefare does not check if keyType is actually valid so we have to
	// do that instead.
	if keyType != KEY_A && keyType != KEY_B {
		return Error(PARAMETER_ERROR)
	}

	r, err := C.mifare_classic_authenticate(
		t.ctag,
		C.MifareClassicBlockNumber(block),
		(*C.uchar)(&key[0]),
		C.MifareClassicKeyType(keyType),
	)

	if r == 0 {
		return nil
	}

	return t.resolveError(err)
}

// Read a block of data from a Mifare Classic tag. Notice that this function has
// been renamed to avoid confusion with the Read() function from io.Reader.
func (t ClassicTag) ReadBlock(block byte) ([16]byte, error) {
	cdata := C.MifareClassicBlock{}

	r, err := C.mifare_classic_read(t.ctag, C.MifareClassicBlockNumber(block), &cdata)
	if r == 0 {
		bdata := [16]byte{}
		for i, d := range cdata {
			bdata[i] = byte(d)
		}

		return bdata, nil
	}

	return [16]byte{}, t.resolveError(err)
}

// Write a block of data to a Mifare Classic tag. Notice that this function has
// been renamed to avoid confusion with the Write() function from io.Writer.
func (t ClassicTag) WriteBlock(block byte, data [16]byte) error {
	r, err := C.mifare_classic_write(
		t.ctag,
		C.MifareClassicBlockNumber(block), (*C.uchar)(&data[0]),
	)

	if r == 0 {
		return nil
	}

	return t.resolveError(err)
}

// Increment the given value block by the provided amount
func (t ClassicTag) Increment(block byte, amount uint32) error {
	r, err := C.mifare_classic_increment(
		t.ctag,
		C.MifareClassicBlockNumber(block),
		C.uint32_t(amount),
	)

	if r == 0 {
		return nil
	}

	return t.resolveError(err)
}

// Decrement the given value block by the provided amount
func (t ClassicTag) Decrement(block byte, amount uint32) error {
	r, err := C.mifare_classic_decrement(
		t.ctag,
		C.MifareClassicBlockNumber(block),
		C.uint32_t(amount),
	)

	if r == 0 {
		return nil
	}

	return t.resolveError(err)
}

// Restore the content of a block
func (t ClassicTag) Restore(block byte) error {
	r, err := C.mifare_classic_restore(t.ctag, C.MifareClassicBlockNumber(block))
	if r == 0 {
		return nil
	}

	return t.resolveError(err)
}

// Transfer the internal data register to the provided block
func (t ClassicTag) Transfer(block byte) error {
	r, err := C.mifare_classic_transfer(t.ctag, C.MifareClassicBlockNumber(block))
	if r >= 0 {
		return nil
	}

	return t.resolveError(err)
}

// Mifare Classic access bits
const (
	MCAB_I = 1 << iota
	MCAB_D
	MCAB_W
	MCAB_R
)

// Other Mifare Classic constants
const (
	MCAB_WRITE_KEYB = 1 << (2 * iota)
	MCAB_READ_KEYB
	MCAB_WRITE_ACCESS_BITS
	MCAB_READ_ACCESS_BITS
	MCAB_WRITE_KEYA
	MCAB_READ_KEYA
)

// Get information about the trailer block. Use the provided constants for
// keyType. This function doesn't work for block 0.
func (t ClassicTag) TrailerBlockPermission(block byte, permission uint16, keyType int) (bool, error) {
	if keyType != KEY_A && keyType != KEY_B {
		return false, Error(PARAMETER_ERROR)
	}

	// Apparently, the libfreefare doesn't check if the tag actually is a
	// Mifare Classic tag in this function. Let's do it ourselves.
	if t := t.Type(); t != CLASSIC_1K && t != CLASSIC_4K {
		return false, Error(INVALID_TAG_TYPE)
	}

	r, err := C.mifare_classic_get_trailer_block_permission(
		t.ctag,
		C.MifareClassicBlockNumber(block),
		C.uint16_t(permission),
		C.MifareClassicKeyType(keyType),
	)

	// The return value itself is meaningful in this function. Hopefully an
	// unmarked authentication error cannot occur.
	if err == nil {
		return r == 1, nil
	}

	return false, t.resolveError(err)
}

// Get information about data blocks
func (t ClassicTag) DataBlockPermission(block, permission byte, keyType int) (bool, error) {
	if keyType != KEY_A && keyType != KEY_B {
		return false, Error(PARAMETER_ERROR)
	}

	// Apparently, the libfreefare doesn't check if the tag actually is a
	// Mifare Classic tag in this function. Let's do it ourselves.
	if t := t.Type(); t != CLASSIC_1K && t != CLASSIC_4K {
		return false, Error(INVALID_TAG_TYPE)
	}

	r, err := C.mifare_classic_get_data_block_permission(
		t.ctag,
		C.MifareClassicBlockNumber(block),
		C.uchar(permission),
		C.MifareClassicKeyType(keyType),
	)

	// The return value itself is meaningful in this function. Hopefully an
	// unmarked authentication error cannot occur.
	if err == nil {
		return r == 1, nil
	}

	return false, t.resolveError(err)
}

// Reset a Mifare Classic target sector to factory default
func (t ClassicTag) FormatSector(sector byte) error {
	r, err := C.mifare_classic_format_sector(t.ctag, C.MifareClassicSectorNumber(sector))
	if r == 0 {
		return nil
	}

	return t.resolveError(err)
}

// Compute a Mifare Classic sector number from a block number
func ClassicBlockSector(block byte) (sector byte) {
	if block < 32*4 {
		sector = block / 4
	} else {
		sector = 32 + (block-32*4)/16
	}

	return
}

// Compute a Mifare Classic sector's first block number
func ClassicSectorFirstBlock(sector byte) (block byte) {
	if sector < 32 {
		block = sector * 4
	} else {
		block = 32*4 + (sector-32)*16
	}

	return
}

// Compute the number of blocks in a Mifare Classic sector
func ClassicSectorBlockCount(sector byte) int {
	if sector < 32 {
		return 4
	} else {
		return 16
	}
}

// Get a Mifare Classic sector's last block number (i.e. trailer block)
func ClassicSectorLastBlock(sector byte) (block byte) {
	block = ClassicSectorFirstBlock(sector) + byte(ClassicSectorBlockCount(sector)) - 1
	return
}
