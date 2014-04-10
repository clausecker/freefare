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
#include <freefare.h>

// auxilliary typedefs to ease the implementation of
// DESFireTag.DESFireFileSettings
typedef struct {
	uint32_t file_size;
} standard_file;

typedef struct {
	int32_t lower_limit;
	int32_t upper_limit;
	int32_t limited_credit_value;
	uint8_t limited_credit_enabled;
} value_file;

typedef struct {
	uint32_t record_size;
	uint32_t max_number_of_records;
	uint32_t current_number_of_records;
} linear_record_file;
*/
import "C"
import "strconv"
import "unsafe"

// DESFire file types as used in DESFireFileSettings
const (
	StandardDataFile = iota
	BackupDataFile
	ValueFileWithBackup
	LinearRecordFileWithBackup
	CyclicRecordFileWithBackup
)

// Mifare DESFire access rights. This wrapper does not provide the constants
// MDAR_KEY0 ... MDAR_KEY13 as they are just 0 ... 13.
const (
	Free = 0xe
	Deny = 0xf
)

// This type remodels struct mifare_desfire_file_settings. Because Go does not
// support union types, this struct contains all union members laid out
// sequentially. Only the set of members denoted by FileType is valid. Use the
// supplied constants for FileType.
//
// Use the function SplitDESFireAccessRights() to split the AccessRights field.
type DESFireFileSettings struct {
	FileType              byte
	CommunicationSettings byte
	AccessRights          uint16

	// FileType == STANDARD_DATA_FILE || FileType == BACKUP_DATA_FILE
	FileSize uint32

	// FileType == VALUE_FILE_WITH_BACKUP
	LowerLimit, UpperLimit int32
	LimitedCreditValue     int32
	LimitedCreditEnabled   byte

	// FileType == LINEAR_RECORD_FILE_WITH_BACKUP || CYCLIC_RECORD_FILE_WITH_BACKUP
	RecordSize             uint32
	MaxNumberOfRecords     uint32
	CurrentNumberOfRecords uint32
}

// Return a list of files in the selected application
func (t DESFireTag) FileIds() ([]byte, error) {
	var cfiles *C.uint8_t
	var count C.size_t
	r, err := C.mifare_desfire_get_file_ids(t.ctag, &cfiles, &count)
	defer C.free(unsafe.Pointer(cfiles))
	if r != 0 {
		return nil, t.TranslateError(err)
	}

	return C.GoBytes(unsafe.Pointer(cfiles), C.int(count)), nil
}

// Return a list of ISO file identifiers
func (t DESFireTag) IsoFileIds() ([]uint16, error) {
	var cfiles *C.uint16_t
	var count C.size_t
	r, err := C.mifare_desfire_get_iso_file_ids(t.ctag, &cfiles, &count)
	defer C.free(unsafe.Pointer(cfiles))
	if r != 0 {
		return nil, t.TranslateError(err)
	}

	// Cutting corners here
	ids := make([]uint16, int(count))
	C.memcpy(unsafe.Pointer(&ids[0]), unsafe.Pointer(cfiles), count)

	return ids, nil
}

// Create an uint16 out of individual access rights. This function only looks
// at the low nibbles of each parameter. This function implements the
// functionality of the MDAR macro from the freefare.h header.
func MakeDESFireAccessRights(read, write, readWrite, changeAccessRights byte) uint16 {
	ar := uint16(read&0xf) << 12
	ar |= uint16(write&0xf) << 8
	ar |= uint16(readWrite&0xf) << 4
	ar |= uint16(changeAccessRights&0xf) << 0
	return ar
}

// Split an access rights block into individual access rights. This function
// implements the functionality of the MDAR_### family of macros.
func SplitDESFireAccessRights(ar uint16) (read, write, readWrite, changeAccessRights byte) {
	read = byte(ar >> 12 & 0xf)
	write = byte(ar >> 8 & 0xf)
	readWrite = byte(ar >> 4 & 0xf)
	changeAccessRights = byte(ar >> 0 & 0xf)
	return
}

// Retrieve the settings of the file fileNo of the selected application of t.
func (t DESFireTag) FileSettings(fileNo byte) (DESFireFileSettings, error) {
	var cfs C.struct_mifare_desfire_file_settings
	r, err := C.mifare_desfire_get_file_settings(t.ctag, C.uint8_t(fileNo), &cfs)
	if r != 0 {
		// explicitly invalid FileType. Behavior is subject to change.
		return DESFireFileSettings{FileType: 0xff}, t.TranslateError(err)
	}

	fs := DESFireFileSettings{
		FileType:              byte(cfs.file_type),
		CommunicationSettings: byte(cfs.communication_settings),
		AccessRights:          uint16(cfs.access_rights),
	}

	sptr := unsafe.Pointer(&cfs.settings[0])
	switch fs.FileType {
	case StandardDataFile:
		fallthrough
	case BackupDataFile:
		sf := (*C.standard_file)(sptr)
		fs.FileSize = uint32(sf.file_size)

	case ValueFileWithBackup:
		vf := (*C.value_file)(sptr)
		fs.LowerLimit = int32(vf.lower_limit)
		fs.UpperLimit = int32(vf.upper_limit)
		fs.LimitedCreditValue = int32(vf.limited_credit_value)
		fs.LimitedCreditEnabled = byte(vf.limited_credit_enabled)

	case LinearRecordFileWithBackup:
		fallthrough
	case CyclicRecordFileWithBackup:
		lrf := (*C.linear_record_file)(sptr)
		fs.RecordSize = uint32(lrf.record_size)
		fs.MaxNumberOfRecords = uint32(lrf.max_number_of_records)
		fs.CurrentNumberOfRecords = uint32(lrf.current_number_of_records)

	default:
		panic("Unexpected file type " + strconv.Itoa(int(fs.FileType)))
	}

	return fs, nil
}

// Change the communication settings and access rights of file fileNo of the
// selected application of t. Use the function MakeDESFireAccessRights() to
// create a suitable accessRights parameter.
func (t DESFireTag) ChangeFileSettings(fileNo, communicationSettings byte, accessRights uint16) error {
	r, err := C.mifare_desfire_change_file_settings(
		t.ctag, C.uint8_t(fileNo), C.uint8_t(communicationSettings), C.uint16_t(accessRights))
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Create a standard or backup data file of size fileSize. This function wraps
// either mifare_desfire_create_std_data_file() or
// mifare_desfire_create_backup_data_file() depending on the value of isBackup.
func (t DESFireTag) CreateDataFile(
	fileNo byte,
	communicationSettings byte,
	accessRights uint16,
	fileSize uint32,
	isBackup bool,
) error {
	var r C.int
	var err error

	if isBackup {
		r, err = C.mifare_desfire_create_std_data_file(
			t.ctag, C.uint8_t(fileNo),
			C.uint8_t(communicationSettings),
			C.uint16_t(accessRights), C.uint32_t(fileSize))
	} else {
		r, err = C.mifare_desfire_create_backup_data_file(
			t.ctag, C.uint8_t(fileNo),
			C.uint8_t(communicationSettings),
			C.uint16_t(accessRights), C.uint32_t(fileSize))
	}

	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Create a standard or backup data file of size fileSize with an ISO file ID.
// This function wraps either mifare_desfire_create_std_data_file_iso() or
// mifare_desfire_create_backup_data_file_iso() depending on the value of
// isBackup.
func (t DESFireTag) CreateDataFileIso(
	fileNo byte,
	communicationSettings byte,
	accessRights uint16,
	fileSize uint32,
	isoFileId uint16,
	isBackup bool,
) error {
	var r C.int
	var err error

	if isBackup {
		r, err = C.mifare_desfire_create_std_data_file_iso(
			t.ctag, C.uint8_t(fileNo),
			C.uint8_t(communicationSettings),
			C.uint16_t(accessRights), C.uint32_t(fileSize),
			C.uint16_t(isoFileId))
	} else {
		r, err = C.mifare_desfire_create_backup_data_file_iso(
			t.ctag, C.uint8_t(fileNo),
			C.uint8_t(communicationSettings),
			C.uint16_t(accessRights), C.uint32_t(fileSize),
			C.uint16_t(isoFileId))
	}

	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Create a value file of value value constrained in the range lowerLimit to
// upperLimit and with the limitedCreditEnable settings.
func (t DESFireTag) CreateValueFile(
	fileNo byte,
	communicationSettings byte,
	accessRights uint16,
	lowerLimit, upperLimit, value int32,
	limitedCreditEnable byte,
) error {
	r, err := C.mifare_desfire_create_value_file(
		t.ctag, C.uint8_t(fileNo),
		C.uint8_t(communicationSettings),
		C.uint16_t(accessRights), C.int32_t(lowerLimit),
		C.int32_t(upperLimit), C.int32_t(value),
		C.uint8_t(limitedCreditEnable))
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Create linear or cyclic record file that can holf maxNumberOfRecords of size
// recordSize. This function wraps either
// mifare_desfire_create_linear_record_file() or
// mifare_desfire_create_cyclic_record_file() depending on the value of the
// isCyclic parameter.
func (t DESFireTag) CreateRecordFile(
	fileNo byte,
	communicationSettings byte,
	accessRights uint16,
	recordSize uint32,
	maxNumberOfRecords uint32,
	isCyclic bool,
) error {
	var r C.int
	var err error
	if isCyclic {
		r, err = C.mifare_desfire_create_cyclic_record_file(
			t.ctag, C.uint8_t(fileNo),
			C.uint8_t(communicationSettings),
			C.uint16_t(accessRights), C.uint32_t(recordSize),
			C.uint32_t(maxNumberOfRecords))
	} else {
		r, err = C.mifare_desfire_create_linear_record_file(
			t.ctag, C.uint8_t(fileNo),
			C.uint8_t(communicationSettings),
			C.uint16_t(accessRights), C.uint32_t(recordSize),
			C.uint32_t(maxNumberOfRecords))
	}

	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Create linear or cyclic record file that can holf maxNumberOfRecords of size
// recordSize with an ISO file ID. This function wraps either
// mifare_desfire_create_linear_record_file_iso() or
// mifare_desfire_create_cyclic_record_file_iso() depending on the value of the
// isCyclic parameter.
func (t DESFireTag) CreateRecordFileIso(
	fileNo byte,
	communicationSettings byte,
	accessRights uint16,
	recordSize uint32,
	maxNumberOfRecords uint32,
	isoFileId uint16,
	isCyclic bool,
) error {
	var r C.int
	var err error
	if isCyclic {
		r, err = C.mifare_desfire_create_cyclic_record_file_iso(
			t.ctag, C.uint8_t(fileNo),
			C.uint8_t(communicationSettings),
			C.uint16_t(accessRights), C.uint32_t(recordSize),
			C.uint32_t(maxNumberOfRecords), C.uint16_t(isoFileId))
	} else {
		r, err = C.mifare_desfire_create_linear_record_file_iso(
			t.ctag, C.uint8_t(fileNo),
			C.uint8_t(communicationSettings),
			C.uint16_t(accessRights), C.uint32_t(recordSize),
			C.uint32_t(maxNumberOfRecords), C.uint16_t(isoFileId))
	}

	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}

// Remove the file fileNo from the selected application
func (t DESFireTag) DeleteFile(fileNo byte) error {
	r, err := C.mifare_desfire_delete_file(t.ctag, C.uint8_t(fileNo))
	if r != 0 {
		return t.TranslateError(err)
	}

	return nil
}
