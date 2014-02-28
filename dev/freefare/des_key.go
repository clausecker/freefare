package freefare

// #include <freefare.h>
import "C"

// This structure wraps a MifareDESFireKey.
type DESFireKey struct {
	key C.MifareDESFireKey

	// The singleton pointer makes sure that the instance of a Tag that
	// carries the finalizer is referenced as long as there is any copy of
	// it is around. This makes sure that the finalizer is not run to early.
	singleton *DESFireKey
}

// TODO
