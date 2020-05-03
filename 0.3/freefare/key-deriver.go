package freefare

// #include <freefare.h>
import "C"

type MifareKeyType int

const (
	MIFARE_KEY_DES MifareKeyType = iota
	MIFARE_KEY_2K3DES
	MIFARE_KEY_3K3DES
	MIFARE_KEY_AES128
)

type MifareKeyDeriver struct {
	tag     *tag
	deriver C.MifareKeyDeriver
}

func (d *MifareKeyDeriver) Begin() error {
	r, err := C.mifare_key_deriver_begin(d.deriver)
	if r == 0 {
		return nil
	}

	return d.tag.TranslateError(err)
}

func (d *MifareKeyDeriver) UpdateUID() error {
	r, err := C.mifare_key_deriver_update_uid(d.deriver, d.tag.ctag)
	if r == 0 {
		return nil
	}

	return d.tag.TranslateError(err)
}

func (d *MifareKeyDeriver) End() (*DESFireKey, error) {
	key, err := C.mifare_key_deriver_end(d.deriver)
	if key != nil {
		return wrapDESFireKey(key), nil
	}

	return nil, d.tag.TranslateError(err)
}
