package freefare

// #include <freefare.h>
import "C"
import "unsafe"

// A Mifare DESFire application ID. For performance reasons, the DESFireAid
// functionality has been reimplemented in Go instead of wrapping C code.
// You can safely do something like this when interfacing with C code:
//
//     aid := NewDESFireAid(0x1234)
//     caid := C.MifareDESFireAid(unsafe.Pointer(aid))
type DESFireAid [3]byte

// Create a new Mifare DESFire Aid. This function ignores the high eight bits of
// aid.
func NewDESFireAid(aid uint32) (m DESFireAid) {
	m[0] = byte(aid >> 0)
	m[1] = byte(aid >> 8)
	m[2] = byte(aid >> 16)
	return
}

// Create a new Mifare DESFire Aid using a Mifare Classic Aid and n as the last
// nibble of the new Aid. This function ease the MifareDESFireAid creation using
// a Mifare Classic Aid (see MIFARE Application Directory document - section
// 3.10 MAD and MIFARE DESFire). This function ignores the most-significant four
// bits of n.
func NewDESFireAidWithMadAid(ma MadAid, n byte) DESFireAid {
	ac, fcc := ma.Content()
	return NewDESFireAid(0xf0000 | uint32(fcc)<<12 | uint32(ac)<<4 | uint32(n))
}

// Return an integer representationn
func (aid DESFireAid) Aid() uint32 {
	return uint32(aid[0]) | uint32(aid[1])<<8 | uint32(aid[2])<<12
}

// Return a pointer typed C.MifareDESFireAid for convenience
func (aid *DESFireAid) cptr() C.MifareDESFireAID {
	return C.MifareDESFireAID(unsafe.Pointer(aid))
}
