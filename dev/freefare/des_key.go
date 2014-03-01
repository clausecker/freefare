package freefare

// #include <freefare.h>
import "C"

// This structure wraps a MifareDESFireKey.
type DESFireKey struct {
	key C.MifareDESFireKey
	*finalizee
}

// TODO
