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

// Encode data stream into TLV. This function expects that len(istream) < 65536.
// Iff this doesn't hold, this function returns nil. This function implements
// the functionality of tlv_encode().
func TLVencode(istream []byte, t byte) []byte {
	if len(istream) >= 0xffff {
		return nil
	}

	var res []byte
	if len(istream) > 254 {
		res = make([]byte, 4, len(istream)+5)
		res[0] = t
		res[1] = 0xff
		res[2] = byte(len(istream) >> 8)
		res[3] = byte(len(istream) >> 0)
	} else {
		res = make([]byte, 2, len(istream)+3)
		res[0] = t
		res[1] = byte(len(istream))
	}

	// copy should not occur, but better be safe
	res = append(res, istream...)
	res = append(res, 0xfe) // TLV_TERMINATOR

	return res
}

// Decode TLV from data stream. This function implements the functionality of
// tlv_decode().
func TLVdecode(istream []byte) (ostream []byte, t byte) {
	t = istream[0]
	fls, fvs := TLVrecordLength(istream)

	res := make([]byte, fvs)
	copy(res, istream[1+fls:])

	return res, t
}

// Get field length size (fls) and field value size (fvs) of a TLV record. This
// function implements the functionality of tlv_record_length().
func TLVrecordLength(istream []byte) (fls, fvs int) {
	switch istream[0] {
	case 0x00:
	case 0xfe:
	case 0x01:
		fallthrough
	case 0x02:
		fallthrough
	case 0x03:
		fallthrough
	default:
		if istream[1] == 0xff {
			fls = 3
			fvs = int(istream[2])<<8 + int(istream[3])<<0
		} else {
			fls = 1
			fvs = int(istream[1])
		}
	}

	return
}
