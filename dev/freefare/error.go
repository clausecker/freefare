package freefare

// #include <freefare.h>
import "C"
import "strconv"
import "syscall"

// PICC and PCD status and error codes. This wrapper will return nil on success,
// expect to not see OPERATION_OK anywhere.
const (
	OPERATION_OK          = 0x00
	CRYPTO_ERROR          = 0x01
	NO_CHANGES            = 0x0C
	OUT_OF_EEPROM_ERROR   = 0x0E
	ILLEGAL_COMMAND_CODE  = 0x1C
	INTEGRITY_ERROR       = 0x1E
	NO_SUCH_KEY           = 0x40
	LENGTH_ERROR          = 0x7E
	PERMISSION_ERROR      = 0x9D
	PARAMETER_ERROR       = 0x9E
	APPLICATION_NOT_FOUND = 0xA0
	APPL_INTEGRITY_ERROR  = 0xA1
	AUTHENTICATION_ERROR  = 0xAE
	ADDITIONAL_FRAME      = 0xAF
	BOUNDARY_ERROR        = 0xBE
	PICC_INTEGRITY_ERROR  = 0xC1
	COMMAND_ABORTED       = 0xCA
	PICC_DISABLED_ERROR   = 0xCD
	COUNT_ERROR           = 0xCE
	DUPLICATE_ERROR       = 0xDE
	EEPROM_ERROR          = 0xEE
	FILE_NOT_FOUND        = 0xF0
	FILE_INTEGRITY_ERROR  = 0xF1
)

// Status and error codes used by this wrapper in addition to the PICC / PCD
// codes. These are mostly errno values represented in a more useful way.
const (
	// libfreefare versions up to 0.4.0 do not set errno on authentication
	// failure. Instead you will see this unknown error which may or may not
	// indicate an authentication failure. AUTHENTICATION_ERROR is returned
	// on newer versions.
	UNKNOWN_ERROR = 0x100 + iota

	// The tag was inactive when it was expected to be active or vice versa
	TAG_STATE_ERROR
	INVALID_TAG_TYPE
	MAD_VERSION_NOTSUP // MAD version not supported
)

// error strings for the errors above
var errorStrings = map[Error]string{
	OPERATION_OK:          "operation OK",
	CRYPTO_ERROR:          "cryptography error",
	NO_CHANGES:            "no changes",
	OUT_OF_EEPROM_ERROR:   "out of EEPROM",
	ILLEGAL_COMMAND_CODE:  "illegal command code",
	INTEGRITY_ERROR:       "integrity error",
	NO_SUCH_KEY:           "no such key",
	LENGTH_ERROR:          "length error",
	PERMISSION_ERROR:      "permission error",
	PARAMETER_ERROR:       "parameter error",
	APPLICATION_NOT_FOUND: "application not found",
	APPL_INTEGRITY_ERROR:  "application integrity error",
	AUTHENTICATION_ERROR:  "authentication failed",
	ADDITIONAL_FRAME:      "addition frame",
	BOUNDARY_ERROR:        "boundary error",
	PICC_INTEGRITY_ERROR:  "PICC integrity error",
	COMMAND_ABORTED:       "command aborted",
	PICC_DISABLED_ERROR:   "PICC disabled error",
	DUPLICATE_ERROR:       "duplicate error",
	EEPROM_ERROR:          "EEPROM error",
	FILE_NOT_FOUND:        "file not found",
	FILE_INTEGRITY_ERROR:  "file integrity error",

	UNKNOWN_ERROR:      "unknown error",
	TAG_STATE_ERROR:    "tag state error",
	INVALID_TAG_TYPE:   "invalid tag type",
	MAD_VERSION_NOTSUP: "MAD version not supported",
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

// Figure out what kind of error happened and translate it into out error codes.
// Pass the error value you got from the libfreefare if available. This function
// panics if e is not nil and not of type syscall.Errno.
func (t *Tag) resolveError(e error) error {
	if e == nil {
		return Error(UNKNOWN_ERROR)
	}

	switch e.(syscall.Errno) {
	case syscall.EBADF:
		// In mifare_application_read(), libfreefare 0.4.0 does not
		// check if malloc failed and wrongly reports EBADF if malloc
		// instead.
		return Error(APPLICATION_NOT_FOUND)
	case syscall.EINVAL:
		return Error(PARAMETER_ERROR)
	case syscall.ENODEV:
		return Error(INVALID_TAG_TYPE)
	case syscall.ENXIO:
		return Error(TAG_STATE_ERROR)
	case syscall.ENOTSUP:
		return Error(MAD_VERSION_NOTSUP)
	case syscall.EPERM:
		return Error(PERMISSION_ERROR)
	case syscall.EACCES:
		return Error(AUTHENTICATION_ERROR)
	case syscall.ENOMEM:
		// Not an error we want to bubble up. malloc() should never fail
		// and if it does, the Go runtime usually panics. So do we.
		panic("C.malloc() returned nil (out of memory)")
	case syscall.EIO:
		if t.Type() == DESFIRE {
			return DESFireTag{t}.resolveEIO()
		} else {
			return t.dev.LastError()
		}
	default:
		// This should not happen, but in case the libfreefare decides
		// to 
		return e
	}
}
