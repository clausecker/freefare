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

// Read bytes from data file fileNo at offset offset. This function returns the
// number of bytes read or an error. As opposed to the underlying function
// mifare_desfire_read_data(), there is no mechanism to read all data from the
// file, this function is a nop if len(buf) == 0. Try passing a large enough
// buffer instead.
//
// This function wraps either mifare_desfire_read_data() or
// mifare_desfire_read_data_ex(), depending on the value of t.ReadSettings.
func (t DESFireTag) ReadData(fileNo byte, offset int64, buf []byte) (int, error) {
	// BUG(libfreefare) The libfreefare <= 0.4.0 may use more bytes of buf
	// than available; memory corruption may happen. I have yet to figure
	// out how to mitigate this issue.

	// sanity checks first. This function uses an int64 for offset to be
	// similar to the io.ReaderAt interface
	if offset < 0 {
		return -1, Error(PARAMETER_ERROR)
	}

	if len(buf) == 0 {
		return 0, nil
	}

	var r C.ssize_t
	var err error
	if t.ReadSettings == DEFAULT {
		r, err = C.mifare_desfire_read_data(
			t.ctag, C.uint8_t(fileNo), C.off_t(offset),
			C.size_t(len(buf)), unsafe.Pointer(&buf[0]))
	} else {
		r, err = C.mifare_desfire_read_data_ex(
			t.ctag, C.uint8_t(fileNo), C.off_t(offset),
			C.size_t(len(buf)), unsafe.Pointer(&buf[0]),
			C.int(t.WriteSettings))
	}

	if r < 0 {
		return int(r), t.TranslateError(err)
	}

	return int(r), nil
}

// Write bytes to data file fileNo at offset offset. This function returns the
// number of bytes written or an error.
//
// This function wraps either mifare_desfire_write_data() or
// mifare_desfire_write_data_ex(), depending on the value of t.WriteSettings.
func (t DESFireTag) WriteData(fileNo byte, offset int64, buf []byte) (int, error) {
	// sanity checks first. This function uses an int64 for offset to be
	// similar to the io.ReaderAt interface
	if offset < 0 {
		return -1, Error(PARAMETER_ERROR)
	}

	var r C.ssize_t
	var err error
	if t.WriteSettings == DEFAULT {
		r, err = C.mifare_desfire_write_data(
			t.ctag, C.uint8_t(fileNo), C.off_t(offset),
			C.size_t(len(buf)), unsafe.Pointer(&buf[0]))
	} else {
		r, err = C.mifare_desfire_write_data_ex(
			t.ctag, C.uint8_t(fileNo), C.off_t(offset),
			C.size_t(len(buf)), unsafe.Pointer(&buf[0]),
			C.int(t.WriteSettings))
	}

	if r < 0 {
		return int(r), t.TranslateError(err)
	}

	return int(r), nil
}

// Read the value of value file fileNo.
//
// This function wraps either mifare_desfire_get_value() or
// mifare_desfire_get_value_ex(), depending on the value of t.ReadSettings.
func (t DESFireTag) Value(fileNo byte) (int32, error) {
	var r C.int
	var err error
	var val C.int32_t
	if t.ReadSettings == DEFAULT {
		r, err = C.mifare_desfire_get_value(
			t.ctag, C.uint8_t(fileNo), &val)
	} else {
		r, err = C.mifare_desfire_get_value_ex(
			t.ctag, C.uint8_t(fileNo), &val, C.int(t.ReadSettings))
	}

	if r != 0 {
		return -1, t.TranslateError(err)
	}

	return int32(val), nil
}

// Add amount to the value of the file fileNo.
//
// This function wraps either mifare_desfire_credit() or
// mifare_desfire_credit_ex(), depending on the value of t.WriteSettings.
func (t DESFireTag) Credit(fileNo byte, amount int32) error {
	var r C.int
	var err error
	if t.WriteSettings == DEFAULT {
		r, err = C.mifare_desfire_credit(
			t.ctag, C.uint8_t(fileNo), C.int32_t(amount))
	} else {
		r, err = C.mifare_desfire_credit_ex(
			t.ctag, C.uint8_t(fileNo), C.int32_t(amount),
			C.int(t.WriteSettings))
	}

	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Subtract amount from the value of the file fileNo.
//
// This function wraps either mifare_desfire_debit() or
// mifare_desfire_debit_ex(), depending on the value of t.WriteSettings.
func (t DESFireTag) Debit(fileNo byte, amount int32) error {
	var r C.int
	var err error
	if t.WriteSettings == DEFAULT {
		r, err = C.mifare_desfire_debit(
			t.ctag, C.uint8_t(fileNo), C.int32_t(amount))
	} else {
		r, err = C.mifare_desfire_debit_ex(
			t.ctag, C.uint8_t(fileNo), C.int32_t(amount),
			C.int(t.WriteSettings))
	}

	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Add amount to the value of the file fileNo.
//
// This function wraps either mifare_desfire_credit() or
// mifare_desfire_credit_ex(), depending on the value of t.WriteSettings.
func (t DESFireTag) LimitedCredit(fileNo byte, amount int32) error {
	var r C.int
	var err error
	if t.WriteSettings == DEFAULT {
		r, err = C.mifare_desfire_limited_credit(
			t.ctag, C.uint8_t(fileNo), C.int32_t(amount))
	} else {
		r, err = C.mifare_desfire_limited_credit_ex(
			t.ctag, C.uint8_t(fileNo), C.int32_t(amount),
			C.int(t.WriteSettings))
	}

	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Write len(data) records starting at record from data to the record file
// fileNo and return the number of bytes written or an error.
//
// This function wraps either mifare_desfire_write_record() or
// mifare_desfire_write_record_ex(), depending on the value of t.WriteSettings.
func (t DESFireTag) WriteRecord(fileNo byte, offset int64, buf []byte) (int, error) {
	// sanity checks first. This function uses an int64 for offset to be
	// similar to the io.ReaderAt interface
	if offset < 0 {
		return -1, Error(PARAMETER_ERROR)
	}

	var r C.ssize_t
	var err error
	if t.WriteSettings == DEFAULT {
		r, err = C.mifare_desfire_write_record(
			t.ctag, C.uint8_t(fileNo), C.off_t(offset),
			C.size_t(len(buf)), unsafe.Pointer(&buf[0]))
	} else {
		r, err = C.mifare_desfire_write_record_ex(
			t.ctag, C.uint8_t(fileNo), C.off_t(offset),
			C.size_t(len(buf)), unsafe.Pointer(&buf[0]),
			C.int(t.WriteSettings))
	}

	if r < 0 {
		return int(r), t.TranslateError(err)
	}

	return int(r), nil
}

// Read len(data) records starting at record offset from the record file fileNo
// and copy them to data, returning the number of bytes read or an error.
//
// This function wraps either mifare_desfire_read_records() or
// mifare_desfire_read_records_ex(), depending on the value of t.ReadSettings.
func (t DESFireTag) ReadRecords(fileNo byte, offset int64, buf []byte) (int, error) {
	// BUG(libfreefare) The libfreefare <= 0.4.0 may use more bytes of buf
	// than available; memory corruption may happen. I have yet to figure
	// out how to mitigate this issue.

	// sanity checks first. This function uses an int64 for offset to be
	// similar to the io.ReaderAt interface
	if offset < 0 {
		return -1, Error(PARAMETER_ERROR)
	}

	if len(buf) == 0 {
		return 0, nil
	}

	var r C.ssize_t
	var err error
	if t.ReadSettings == DEFAULT {
		r, err = C.mifare_desfire_read_records(
			t.ctag, C.uint8_t(fileNo), C.off_t(offset),
			C.size_t(len(buf)), unsafe.Pointer(&buf[0]))
	} else {
		r, err = C.mifare_desfire_read_records_ex(
			t.ctag, C.uint8_t(fileNo), C.off_t(offset),
			C.size_t(len(buf)), unsafe.Pointer(&buf[0]),
			C.int(t.WriteSettings))
	}

	if r < 0 {
		return int(r), t.TranslateError(err)
	}

	return int(r), nil
}

// Erase all records from the record file fileNo
func (t DESFireTag) ClearRecordFile(fileNo byte) error {
	r, err := C.mifare_desfire_clear_record_file(t.ctag, C.uint8_t(fileNo))
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Validate pending changes to the tag.
func (t DESFireTag) CommitTransaction() error {
	r, err := C.mifare_desfire_commit_transaction(t.ctag)
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Roll back pending changes to the tag.
func (t DESFireTag) AbortTransaction() error {
	r, err := C.mifare_desfire_abort_transaction(t.ctag)
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}
