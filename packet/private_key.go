package packet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"github.com/murakmii/ZatsuPGP/key"
	"github.com/murakmii/ZatsuPGP/s2k"
	"github.com/murakmii/ZatsuPGP/util"
	"io"
	"math/big"
)

type PrivateKeyPacket struct {
	pub          *key.PublicKey
	s2kFunc      s2k.Func
	iv           []byte
	encryptedKey []byte
}

func DecodePrivateKeyPacket(r io.Reader) (*PrivateKeyPacket, error) {
	pk := &PrivateKeyPacket{}
	var err error

	if pk.pub, err = key.DecodePublicKey(r); err != nil {
		return nil, err
	}

	metadata, err := util.ReadBytes(r, 2)
	if err != nil {
		return nil, err
	}
	if metadata[0] != 254 {
		return nil, errors.New("S2K checksum must be SHA-1")
	}
	if metadata[1] != 7 {
		return nil, errors.New("algorithm of key encryption must be AES-128")
	}

	if pk.s2kFunc, err = s2k.DecodeS2KSpecifier(r); err != nil {
		return nil, err
	}
	if pk.iv, err = util.ReadBytes(r, aes.BlockSize); err != nil {
		return nil, err
	}
	if pk.encryptedKey, err = io.ReadAll(r); err != nil {
		return nil, err
	}

	return pk, nil
}

func (p *PrivateKeyPacket) Type() byte         { return 5 }
func (p *PrivateKeyPacket) EncodeBody() []byte { panic("not implemented") }

func (p *PrivateKeyPacket) PublicKey() *key.PublicKey { return p.pub }
func (p *PrivateKeyPacket) S2KFunc() s2k.Func         { return p.s2kFunc }
func (p *PrivateKeyPacket) IV() []byte                { return p.iv }

func (p *PrivateKeyPacket) Decrypt(passphrase string) (*rsa.PrivateKey, error) {
	block, err := aes.NewCipher(p.s2kFunc.DeriveKey([]byte(passphrase), aes.BlockSize))
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(p.encryptedKey))
	cipher.NewCFBDecrypter(block, p.iv).XORKeyStream(decrypted, p.encryptedKey)

	if len(decrypted) < sha1.Size {
		return nil, errors.New("decrypted private key has invalid format")
	}

	checksum := sha1.Sum(decrypted[:len(decrypted)-sha1.Size])
	if !bytes.Equal(checksum[:], decrypted[len(decrypted)-sha1.Size:]) {
		return nil, errors.New("private key data has invalid checksum")
	}

	r := bytes.NewReader(decrypted)
	numbers := make([]*big.Int, 3)

	for i := 0; i < 3; i++ {
		if numbers[i], err = util.DecodeMPI(r); err != nil {
			return nil, err
		}
	}

	pk := &rsa.PrivateKey{
		PublicKey: *p.pub.Key(),
		D:         numbers[0],
		Primes:    numbers[1:],
	}

	return pk, pk.Validate()
}
