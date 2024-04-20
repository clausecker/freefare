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
import "strconv"
import "syscall"

// PICC and PCD status and error codes. This wrapper will return nil on success,
// expect to not see OPERATION_OK anywhere.
const (
	OperationOK         = 0x00
	CryptoError         = 0x01
	NoChanges           = 0x0C
	OutOfEEPromError    = 0x0E
	IllegalCommandCode  = 0x1C
	IntegrityError      = 0x1E
	NoSuchKey           = 0x40
	LengthError         = 0x7E
	PermissionError     = 0x9D
	ParameterError      = 0x9E
	ApplicationNotFound = 0xA0
	ApplIntegrityError  = 0xA1
	AuthenticationError = 0xAE
	AdditionalFrame     = 0xAF
	BoundaryError       = 0xBE
	PICCIntegrityError  = 0xC1
	CommandAborted      = 0xCA
	PICCDisabledError   = 0xCD
	CountError          = 0xCE
	DuplicateError      = 0xDE
	EEPromError         = 0xEE
	FileNotFound        = 0xF0
	FileIntegrityError  = 0xF1
)

// Status and error codes used by this wrapper in addition to the PICC / PCD
// codes. These are mostly errno values represented in a more useful way.
const (
	// libfreefare versions up to 0.4.0 do not set errno on authentication
	// failure. Instead you will see this unknown error which may or may not
	// indicate an authentication failure. AUTHENTICATION_ERROR is returned
	// on newer versions.
	UnknownError = 0x100 + iota

	// The tag was inactive when it was expected to be active or vice versa
	TagStateError
	InvalidTagType
	MadVersionNotSup // MAD version not supported
)

// error strings for the errors above
var errorStrings = map[Error]string{
	OperationOK:         "operation OK",
	CryptoError:         "cryptography error",
	NoChanges:           "no changes",
	OutOfEEPromError:    "out of EEPROM",
	IllegalCommandCode:  "illegal command code",
	IntegrityError:      "integrity error",
	NoSuchKey:           "no such key",
	LengthError:         "length error",
	PermissionError:     "permission error",
	ParameterError:      "parameter error",
	ApplicationNotFound: "application not found",
	ApplIntegrityError:  "application integrity error",
	AuthenticationError: "authentication failed",
	AdditionalFrame:     "addition frame",
	BoundaryError:       "boundary error",
	PICCIntegrityError:  "PICC integrity error",
	CommandAborted:      "command aborted",
	PICCDisabledError:   "PICC disabled error",
	DuplicateError:      "duplicate error",
	EEPromError:         "EEPROM error",
	FileNotFound:        "file not found",
	FileIntegrityError:  "file integrity error",

	UnknownError:     "unknown error",
	TagStateError:    "tag state error",
	InvalidTagType:   "invalid tag type",
	MadVersionNotSup: "MAD version not supported",
}

// A MIFARE error. Functions in this library that return an error return either
// an object of this type or an object of type nfc.Error if failure occured in
// the libnfc. Values of type Error can be matched against the various symbolic
// constants provided. All values in the range 0x00 to 0xff are unchanged PICC
// or PCD error codes from the libfreefare. Error codes with values higher than
// 0xff are custom additions by this Go wrapper to denote errors communicated
// over errno values.
type Error int

// Get the error string of an Error
func (e Error) Error() string {
	str := errorStrings[e]
	if str == "" {
		// Please report a bug if this happens
		return "Freefare error #" + strconv.Itoa(int(e))
	}

	return str
}

// Translate errno value into Go error. This function can be used in modules
// that wrap C code that use the libfreefare. Use a two-return call to get the
// value of errno and pass errno to TranslateError() if an error occured like
// this:
//
//     ret, errno := C.do_something_with_a_tag(tag.Pointer())
//     if error_occured {
//         err := tag.TranslateError(errno)
//         /* normal error handling with err */
//     }
//
// If e is not a nil pointer and not of type syscall.Errno, this function
// panics.
func (t *tag) TranslateError(e error) error {
	if e == nil {
		return Error(UnknownError)
	}

	switch e.(syscall.Errno) {
	case syscall.EBADF:
		// In mifare_application_read(), libfreefare 0.4.0 does not
		// check if malloc failed and wrongly reports EBADF if malloc
		// instead.
		return Error(ApplicationNotFound)
	case syscall.EINVAL:
		return Error(ParameterError)
	case syscall.ENODEV:
		return Error(InvalidTagType)
	case syscall.ENXIO:
		return Error(TagStateError)
	case syscall.ENOTSUP:
		// Currently the only thing that is unsupported.
		return Error(MadVersionNotSup)
	case syscall.EPERM:
		return Error(PermissionError)
	case syscall.EACCES:
		return Error(AuthenticationError)
	case syscall.ENOMEM:
		// Not an error we want to bubble up. malloc() should never fail
		// and if it does, the Go runtime usually panics. So do we.
		panic("C.malloc() returned nil (out of memory)")
	case syscall.EIO:
		if t.Type() == DESFire {
			return DESFireTag{tag: t}.resolveEIO()
		} else {
			return t.Device().LastError()
		}
	default:
		// This should not happen, but in case the libfreefare decides
		// to suddently return new errors, we should be prepared.
		return e
	}
}
