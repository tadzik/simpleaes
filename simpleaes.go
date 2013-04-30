// Make encryption in Go easy
package simpleaes

import (
    "crypto/aes"
    "crypto/cipher"
)

type Aes struct {
    enc, dec cipher.BlockMode
}

// Creates a new encryption/decryption object
// with a given key of a given size
// (16, 24 or 32 for AES-128, AES-192 and AES-256 respectively,
// as per http://golang.org/pkg/crypto/aes/#NewCipher)
//
// The key will be padded to the given size if needed.
// An IV is created as a series of NULL bytes of necessary length
func New(size int, key string) (*Aes, error) {
    padded := make([]byte, size)
    copy(padded, []byte(key))
    iv := make([]byte, size)
    aes, err := aes.NewCipher(padded)
    if err != nil {
        return nil, err
    }
    enc := cipher.NewCBCEncrypter(aes, iv)
    dec := cipher.NewCBCDecrypter(aes, iv)
    return &Aes{enc, dec}, nil
}

func (me *Aes) padSlice(src []byte) []byte {
    // src must be a multiple of block size
    bs := me.enc.BlockSize()
    mult := int((len(src) / bs) + 1)
    leng := bs * mult

    src_padded := make([]byte, leng)
    copy(src_padded, src)
    return src_padded
}

// Encrypt a slice of bytes, producing a new, freshly allocated slice
//
// Source will be padded with null bytes if necessary
func (me *Aes) Encrypt(src []byte) []byte {
    if (len(src) % me.enc.BlockSize() != 0) {
        src = me.padSlice(src)
    }
    dst := make([]byte, len(src))
    me.enc.CryptBlocks(dst, src)
    return dst
}

// Decrypt a slice of bytes, producing a new, freshly allocated slice
//
// Source will be padded with null bytes if necessary
func (me *Aes) Decrypt(src []byte) []byte {
    if (len(src) % me.dec.BlockSize() != 0) {
        src = me.padSlice(src)
    }
    dst := make([]byte, len(src))
    me.dec.CryptBlocks(dst, src)
    return dst
}
