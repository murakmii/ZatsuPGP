package packet

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"github.com/murakmii/ZatsuPGP/key"
	"io"
)

type (
	EncryptedIntegrityProtectedDataPacket struct {
		encryptedData []byte
	}
)

var mdcPacketHeader = []byte{0xD3, 0x14}
var mdcPacketLen = len(mdcPacketHeader) + sha1.Size

func generateEncryptionPrefix(blockSize int) ([]byte, error) {
	prefix := make([]byte, blockSize+2)
	if _, err := rand.Reader.Read(prefix); err != nil {
		return nil, err
	}

	copy(prefix[blockSize:], prefix[blockSize-2:blockSize])
	return prefix, nil
}

func computeMDCPacket(prefixedData []byte) []byte {
	hashInput := make([]byte, len(prefixedData)+len(mdcPacketHeader))
	copy(hashInput, prefixedData)
	copy(hashInput[len(prefixedData):], mdcPacketHeader)

	h := sha1.Sum(hashInput)
	mdcPacket := make([]byte, mdcPacketLen)

	copy(mdcPacket, mdcPacketHeader)
	copy(mdcPacket[len(mdcPacketHeader):], h[:])
	return mdcPacket
}

func BuildEncryptedIntegrityProtectedDataPacket(pkt Packet, sk key.SessionKey) (*EncryptedIntegrityProtectedDataPacket, error) {
	data := EncodePacket(pkt)
	prefix, err := generateEncryptionPrefix(sk.BlockSize())
	if err != nil {
		return nil, err
	}

	input := make([]byte, len(prefix)+len(data)+mdcPacketLen)
	copy(input, prefix)
	copy(input[len(prefix):], data)

	mdcOffset := len(prefix) + len(data)
	copy(input[mdcOffset:], computeMDCPacket(input[:mdcOffset]))

	encrypted := make([]byte, len(input))
	skBlock, err := sk.Cipher()
	if err != nil {
		return nil, err
	}
	cipher.NewCFBEncrypter(skBlock, make([]byte, sk.BlockSize())).XORKeyStream(encrypted, input)

	return &EncryptedIntegrityProtectedDataPacket{encryptedData: encrypted}, nil
}

func DecodeEncryptedIntegrityProtectedDataPacket(r io.Reader) (*EncryptedIntegrityProtectedDataPacket, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("encrypted data is empty")
	}
	if data[0] != 1 {
		return nil, errors.New("encrypted data version must be 1")
	}

	return &EncryptedIntegrityProtectedDataPacket{encryptedData: data[1:]}, nil
}

func (p *EncryptedIntegrityProtectedDataPacket) Type() byte { return 18 }
func (p *EncryptedIntegrityProtectedDataPacket) EncodeBody() []byte {
	body := make([]byte, len(p.encryptedData)+1)
	body[0] = 1
	copy(body[1:], p.encryptedData)

	return body
}

func (p *EncryptedIntegrityProtectedDataPacket) Decrypt(sk key.SessionKey) ([]Packet, error) {
	decrypted := make([]byte, len(p.encryptedData))
	skBlock, err := sk.Cipher()
	if err != nil {
		return nil, err
	}
	cipher.NewCFBDecrypter(skBlock, make([]byte, sk.BlockSize())).XORKeyStream(decrypted, p.encryptedData)

	prefixLen := sk.BlockSize() + 2
	if len(decrypted) < prefixLen+mdcPacketLen {
		return nil, errors.New("decrypted data has invalid format")
	}

	computedMDC := computeMDCPacket(decrypted[:len(decrypted)-mdcPacketLen])
	if !bytes.Equal(decrypted[len(decrypted)-mdcPacketLen:], computedMDC) {
		return nil, errors.New("decrypted data has invalid MDC")
	}

	return DecodePackets(bytes.NewReader(decrypted[prefixLen:]))
}
