package broadlink

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

var (
	// default AES key and IV for Broadlink device
	broadlink_aeskey = []byte{0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02}
	broadlink_aesiv  = []byte{0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58}

	aesblock, _ = aes.NewCipher(broadlink_aeskey)
)

// Encrypt data using d.aesKey.
func (d *Device) Encrypt(data []byte) []byte {
	return blockCipher(cipher.NewCBCEncrypter(d.cipherParam()), data)
}

// Decrypt packet data using d.aesKey.
func (d *Device) Decrypt(data []byte) []byte {
	// return blockCipher(cipher.NewCBCDecrypter(blk, iv), data)
	return blockCipher(cipher.NewCBCDecrypter(d.cipherParam()), data)
}

// Set a new AES key for the device.
func (d *Device) SetAESKey(key []byte) {
	if len(key) != aes.BlockSize || bytes.Compare(key, broadlink_aeskey) == 0 {
		key = nil
	}
	if key == nil {
		d.aesKey, d.aesBlock = nil, nil
		return
	}
	d.aesKey = make([]byte, len(key))
	copy(d.aesKey, key)
	d.aesBlock, _ = aes.NewCipher(d.aesKey)
}

// Get the devices's current AES key
func (d *Device) GetAESKey() []byte {
	if d.aesKey == nil {
		k := make([]byte, len(broadlink_aeskey))
		copy(k, broadlink_aeskey)
		return k
	}
	return d.aesKey
}

// Run AES cipher function over input data.
// Return data may have additional zero-padding to block boundary.
func blockCipher(m cipher.BlockMode, data []byte) []byte {

	sz := len(data)
	if sz == 0 {
		return nil
	}

	// start position of leftover data
	split := (sz / aes.BlockSize) * aes.BlockSize
	// calculate padding data size
	pad := 0
	if split < sz {
		pad = split + aes.BlockSize - sz
	}

	result := make([]byte, sz+pad)
	m.CryptBlocks(result[:split], data[:split])
	if split < sz {
		// add padding to leftover data and feed to cipher function
		tmp := make([]byte, aes.BlockSize)
		copy(tmp, data[split:])
		m.CryptBlocks(result[split:], tmp)
	}

	return result
}

func (d *Device) cipherParam() (blk cipher.Block, iv []byte) {
	if d.aesIV != nil {
		iv = d.aesIV
	} else {
		iv = broadlink_aesiv
	}
	if d.aesBlock != nil {
		blk = d.aesBlock
	} else {
		blk = aesblock
	}
	return
}
