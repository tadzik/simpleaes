package simpleaes

import (
    "crypto/aes"
    "crypto/cipher"
)

type Aes struct {
    enc, dec cipher.BlockMode
}

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

func (me *Aes) Encrypt(src []byte) []byte {
    if (len(src) % me.enc.BlockSize() != 0) {
        src = me.padSlice(src)
    }
    dst := make([]byte, len(src))
    me.enc.CryptBlocks(dst, src)
    return dst
}

func (me *Aes) Decrypt(src []byte) []byte {
    if (len(src) % me.dec.BlockSize() != 0) {
        src = me.padSlice(src)
    }
    dst := make([]byte, len(src))
    me.dec.CryptBlocks(dst, src)
    return dst
}
