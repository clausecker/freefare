package freefare

// #include <freefare.h>
import "C"
import "errors"
import "syscall"

// this tag wraps the common error handling from all Connect() methods.
func (t *Tag) genericConnect(f func(C.MifareTag) (C.int, error)) error {
	r, err := f(t.tag)
	if r == 0 {
		return nil
	}

	// Now, figure out what exactly went wrong. The mifare_xxx_connect()
	// functions helpfully sets errno to distinct values for each kind of
	// error that can occur.
	if err == nil {
		// This should actually not happen since the libfreefare
		// explicitly sets errno everywhere.
		return errors.New("unknown error")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		// nfc_initiator_select_passive_target failed.
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag already active")
	case syscall.ENODEV:
		return errors.New("Invalid tag type")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		// all possible errors were handled above, but anyway.
		return err
	}
}

// this tag wraps the common error handling from all Connect() methods.
func (t *Tag) genericDisconnect(f func(C.MifareTag) (C.int, error)) error {
	r, err := f(t.tag)
	if r == 0 {
		return nil
	}

	// Error handling as above
	if err == nil {
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag already inactive")
	case syscall.ENODEV:
		return errors.New("invalid tag type")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}
