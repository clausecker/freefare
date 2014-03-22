package freefare

// #include <freefare.h>
import "C"
import "errors"
import "syscall"

// Wrap a Tag into a ClassicTag to access functionality available for
// Mifare Classic tags.
type ClassicTag struct {
	*Tag
}

// Mifare Classic key types
const (
	KEY_A = iota
	KEY_B
)

// Connect to a Mifare Classic tag. This causes the tag to be active.
func (t ClassicTag) Connect() error {
	return t.genericConnect(func(t C.MifareTag) (C.int, error) {
		r, err := C.mifare_classic_connect(t)
		return r, err
	})
}

// Disconnect from a Mifare Classic tag. This causes the tag to be inactive.
func (t ClassicTag) Disconnect() error {
	return t.genericDisconnect(func(t C.MifareTag) (C.int, error) {
		r, err := C.mifare_classic_disconnect(t)
		return r, err
	})
}

// Authenticate against a Mifare Classic tag. Use the provided constants for
// keyType.
func (t ClassicTag) Authenticate(block byte, key [6]byte, keyType int) error {
	// libfreefare does not check if keyType is actually valid so we have to
	// do that instead.
	if keyType != KEY_A && keyType != KEY_B {
		return errors.New("illegal key type")
	}

	r, err := C.mifare_classic_authenticate(
		t.tag,
		C.MifareClassicBlockNumber(block),
		(*C.uchar)(&key[0]),
		C.MifareClassicKeyType(keyType),
	)

	if r == 0 {
		return nil
	}

	// error handling as above.
	if err == nil {
		// libfreefare <= 0.4.0 does not set errno on authentication
		// failure, so assume that authentication failed when errno is
		// not set.
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}

// Read a block of data from a Mifare Classic tag. Notice that this function has
// been renamed to avoid confusion with the Read() function from io.Reader.
func (t ClassicTag) ReadBlock(block byte) ([16]byte, error) {
	cdata := C.MifareClassicBlock{}

	r, err := C.mifare_classic_read(t.tag, C.MifareClassicBlockNumber(block), &cdata)
	if r == 0 {
		bdata := [16]byte{}
		for i, d := range cdata {
			bdata[i] = byte(d)
		}

		return bdata, nil
	}

	// error handling as above
	if err == nil {
		return [16]byte{}, errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return [16]byte{}, t.dev.LastError()
	case syscall.ENXIO:
		return [16]byte{}, errors.New("tag not active")
	case syscall.ENODEV:
		return [16]byte{}, errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return [16]byte{}, errors.New("invalid block")
	case syscall.EACCES:
		return [16]byte{}, errors.New("authentication failed")
	default:
		return [16]byte{}, err
	}
}

// Write a block of data to a Mifare Classic tag. Notice that this function has
// been renamed to avoid confusion with the Write() function from io.Writer.
func (t ClassicTag) WriteBlock(block byte, data [16]byte) error {
	r, err := C.mifare_classic_write(
		t.tag,
		C.MifareClassicBlockNumber(block), (*C.uchar)(&data[0]),
	)

	if r == 0 {
		return nil
	}

	if err == nil {
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return errors.New("invalid block")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}

// Increment the given value block by the provided amount
func (t ClassicTag) Increment(block byte, amount uint32) error {
	r, err := C.mifare_classic_increment(
		t.tag,
		C.MifareClassicBlockNumber(block),
		C.uint32_t(amount),
	)

	if r == 0 {
		return nil
	}

	if err == nil {
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return errors.New("invalid block")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}

// Decrement the given value block by the provided amount
func (t ClassicTag) Decrement(block byte, amount uint32) error {
	r, err := C.mifare_classic_decrement(
		t.tag,
		C.MifareClassicBlockNumber(block),
		C.uint32_t(amount),
	)

	if r == 0 {
		return nil
	}

	if err == nil {
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return errors.New("invalid block")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}

// Restore the content of a block
func (t ClassicTag) Restore(block byte) error {
	r, err := C.mifare_classic_restore(t.tag, C.MifareClassicBlockNumber(block))

	if r == 0 {
		return nil
	}

	if err == nil {
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return errors.New("invalid block")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}

// Transfer the internal data register to the provided block
func (t ClassicTag) Transfer(block byte) error {
	r, err := C.mifare_classic_transfer(t.tag, C.MifareClassicBlockNumber(block))

	if r >= 0 {
		return nil
	}

	if err == nil {
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return errors.New("invalid block")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}

// Mifare Classic access bits
const (
	MCAB_I = 1 << iota
	MCAB_D
	MCAB_W
	MCAB_R
)

// Other Mifare Classic constants
const (
	MCAB_WRITE_KEYB = 1 << (2 * iota)
	MCAB_READ_KEYB
	MCAB_WRITE_ACCESS_BITS
	MCAB_READ_ACCESS_BITS
	MCAB_WRITE_KEYA
	MCAB_READ_KEYA
)

// Get information about the trailer block. Use the provided constants for
// keyType. This function doesn't work for block 0.
func (t ClassicTag) TrailerBlockPermission(block byte, permission uint16, keyType int) (bool, error) {
	if keyType != KEY_A && keyType != KEY_B {
		return false, errors.New("illegal key type")
	}

	// Apparently, the libfreefare doesn't check if the tag actually is a
	// Mifare Classic tag in this function. Let's do it ourselves.
	if t := t.Type(); t != CLASSIC_1K && t != CLASSIC_4k {
		return false, errors.New("tag is not a Mifare Classic tag")
	}

	r, err := C.mifare_classic_get_trailer_block_permission(
		t.tag,
		C.MifareClassicBlockNumber(block),
		C.uint16_t(permission),
		C.MifareClassicKeyType(keyType),
	)

	// The return value itself is meaningful in this function. Hopefully an
	// unmarked authentication error cannot occur.
	if err == nil {
		return r == 1, nil
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return false, t.dev.LastError()
	case syscall.ENXIO:
		return false, errors.New("tag not active")
	case syscall.ENODEV:
		return false, errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return false, errors.New("invalid block")
	case syscall.EACCES:
		return false, errors.New("authentication failed")
	default:
		return false, err
	}
}

// Get information about data blocks
func (t ClassicTag) DataBlockPermission(block, permission byte, keyType int) (bool, error) {
	if keyType != KEY_A && keyType != KEY_B {
		return false, errors.New("illegal key type")
	}

	// Apparently, the libfreefare doesn't check if the tag actually is a
	// Mifare Classic tag in this function. Let's do it ourselves.
	if t := t.Type(); t != CLASSIC_1K && t != CLASSIC_4k {
		return false, errors.New("tag is not a Mifare Classic tag")
	}

	r, err := C.mifare_classic_get_data_block_permission(
		t.tag,
		C.MifareClassicBlockNumber(block),
		C.uchar(permission),
		C.MifareClassicKeyType(keyType),
	)

	// The return value itself is meaningful in this function. Hopefully an
	// unmarked authentication error cannot occur.
	if err == nil {
		return r == 1, nil
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return false, t.dev.LastError()
	case syscall.ENXIO:
		return false, errors.New("tag not active")
	case syscall.ENODEV:
		return false, errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return false, errors.New("invalid block")
	case syscall.EACCES:
		return false, errors.New("authentication failed")
	default:
		return false, err
	}
}

// Reset a Mifare Classic target sector to factory default
func (t ClassicTag) FormatSector(sector byte) error {
	r, err := C.mifare_classic_format_sector(t.tag, C.MifareClassicSectorNumber(sector))
	if r == 0 {
		return nil
	}

	if err == nil {
		return errors.New("authentication failed")
	}

	errno := err.(syscall.Errno)
	switch errno {
	case syscall.EIO:
		return t.dev.LastError()
	case syscall.ENXIO:
		return errors.New("tag not active")
	case syscall.ENODEV:
		return errors.New("tag is not a Mifare Classic tag")
	case syscall.EINVAL:
		return errors.New("invalid block")
	case syscall.EACCES:
		return errors.New("authentication failed")
	default:
		return err
	}
}

// Compute a Mifare Classic sector number from a block number
func ClassicBlockSector(block byte) (sector byte) {
	if block < 32*4 {
		sector = block / 4
	} else {
		sector = 32 + (block-32*4)/16
	}

	return
}

// Compute a Mifare Classic sector's first block number
func ClassicSectorFirstBlock(sector byte) (block byte) {
	if sector < 32 {
		block = sector * 4
	} else {
		block = 32*4 + (sector-32)*16
	}

	return
}

// Compute the number of blocks in a Mifare Classic sector
func ClassicSectorBlockCount(sector byte) int {
	if sector < 32 {
		return 4
	} else {
		return 16
	}
}

// Get a Mifare Classic sector's last block number (i.e. trailer block)
func ClassicSectorLastBlock(sector byte) (block byte) {
	block = ClassicSectorFirstBlock(sector) + byte(ClassicSectorBlockCount(sector)) - 1
	return
}
