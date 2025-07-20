package key

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

type SessionKey []byte

func GenerateSessionKey() (SessionKey, error) {
	sk := make([]byte, 32)
	if _, err := rand.Reader.Read(sk); err != nil {
		return nil, err
	}

	return sk, nil
}

func DecodeSessionKey(encoded []byte) (SessionKey, error) {
	if len(encoded) < 3 {
		return nil, errors.New("invalid session key")
	}
	if encoded[0] != 0x09 {
		return nil, errors.New("session key algorithm must be AES-256")
	}

	sk := encoded[1 : len(encoded)-2]
	csActual := computeSessionKeyChecksum(sk)
	csExpected := binary.BigEndian.Uint16(encoded[len(encoded)-2:])

	if csActual != csExpected {
		return nil, errors.New("checksum of session key is invalid")
	}

	return sk, nil
}

func (sk SessionKey) BlockSize() int {
	return aes.BlockSize
}

func (sk SessionKey) Cipher() (cipher.Block, error) {
	return aes.NewCipher(sk)
}

func (sk SessionKey) Encode() []byte {
	enc := make([]byte, len(sk)+3)

	enc[0] = 0x09
	copy(enc[1:], sk)
	binary.BigEndian.PutUint16(enc[len(sk)+1:], computeSessionKeyChecksum(sk))

	return enc
}

func computeSessionKeyChecksum(key []byte) uint16 {
	var checksum uint16
	for _, s := range key {
		checksum += uint16(s)
	}
	return checksum
}
