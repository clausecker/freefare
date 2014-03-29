package freefare

// #include <freefare.h>
import "C"
import "unsafe"

// This structure wraps a MifareDESFireKey.
type DESFireKey struct {
	key C.MifareDESFireKey
	*finalizee
}

func wrapDESFireKey(k C.MifareDESFireKey) *DESFireKey {
	if k == nil {
		panic("C.malloc() returned nil (out of memory)")
	}

	return &DESFireKey{key: k, finalizee: newFinalizee(unsafe.Pointer(k))}
}

// Create a new DES key. This function wraps the verbosely named function
// mifare_desfire_des_key_new_with_version. To get a result equal to what
// mifare_desfire_des_key_new does, set the version to 0 after creating the key
// or clear the lowest bit of each byte using code like this:
//
//     var value [8]byte
//     /* ... */
//
//     for i := range value {
//         value[i] ^&= 1
//     }
//
//     key := NewDESFireDESKey(value)
func NewDESFireDESKey(value [8]byte) *DESFireKey {
	key := C.mifare_desfire_des_key_new_with_version((*C.uint8_t)(&value[0]))
	return wrapDESFireKey(key)
}

// Create a new 3DES key. This function wraps the verbosely named function
// mifare_desfire_3des_key_new_with_version. To get a result equal to what
// mifare_desfire_3des_key_new does, set the version to 0 after creating the
// key or clear the lowest bits of the first eight bytes and set the lowest bits
// of the last eight using code like this:
//
//     var value [16]byte
//     /* ... */
//
//     for i := 0; i < 8; i++ {
//         value[i] ^&= 1
//     }
//
//     for i := 8; i < 16; i++ {
//         value[i] |= 1
//     }
//
//     key := NewDESFireDES3Key(value)
func NewDESFire3DESKey(value [16]byte) *DESFireKey {
	key := C.mifare_desfire_3des_key_new_with_version((*C.uint8_t)(&value[0]))
	return wrapDESFireKey(key)
}

// Create a new 3K3DES key. This function wraps the verbosely named function
// mifare_desfire_3k3des_key_new_with_version. To get a result equal to what
// mifare_desfire_3k3des_key_new does, set the version to 0 after creating the
// key or clear the lowest bit of each byte using code like this:
//
//     var value [24]byte
//     /* ... */
//
//     for i := 0; i < 8; i++ {
//         value[i] ^&= 1
//     }
//
//     key := NewDESFire3K3DESKey(value)
func NewDESFire3K3DESKey(value [24]byte) *DESFireKey {
	key := C.mifare_desfire_3k3des_key_new_with_version((*C.uint8_t)(&value[0]))
	return wrapDESFireKey(key)
}

// Create a new AES key. This function wraps the verbosely named function
// mifare_desfire_aes_key_new_with_version. To get a result equal to what
// mifare_desfire_aes_key_new does, pass 0 as version.
func NewDESFireAESKey(value [16]byte, version byte) *DESFireKey {
	key := C.mifare_desfire_aes_key_new_with_version((*C.uint8_t)(&value[0]), C.uint8_t(version))
	return wrapDESFireKey(key)
}

// Get the version of a Mifare DESFireKey.
func (k *DESFireKey) Version() byte {
	return byte(C.mifare_desfire_key_get_version(k.key))
}

// Set the version of a Mifare DESFireKey.
func (k *DESFireKey) SetVersion(version byte) {
	C.mifare_desfire_key_set_version(k.key, C.uint8_t(version))
}
