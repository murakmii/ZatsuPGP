package packet

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/murakmii/ZatsuPGP/key"
	"github.com/murakmii/ZatsuPGP/util"
	"io"
	"math/big"
)

type EncryptedSessionKeyPacket struct {
	keyID       []byte
	keyAlg      byte
	encryptedSk []byte
}

func BuildEncryptedSessionKeyPacket(sk key.SessionKey, pub *key.PublicKey) (*EncryptedSessionKeyPacket, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub.Key(), sk.Encode())
	if err != nil {
		return nil, err
	}

	return &EncryptedSessionKeyPacket{
		keyID:       pub.KeyID(),
		keyAlg:      pub.Alg(),
		encryptedSk: encrypted,
	}, nil
}

func DecodeEncryptedSessionKeyPacket(r io.Reader) (*EncryptedSessionKeyPacket, error) {
	metadata, err := util.ReadBytes(r, 10)
	if err != nil {
		return nil, err
	}

	if metadata[0] != 3 || metadata[9] != 1 {
		return nil, errors.New("session key was encrypted by unsupported key")
	}

	pkt := &EncryptedSessionKeyPacket{
		keyID:  metadata[1:9],
		keyAlg: metadata[9],
	}
	
	mpi, err := util.DecodeMPI(r)
	if err != nil {
		return nil, err
	}

	pkt.encryptedSk = mpi.Bytes()
	return pkt, nil
}

func (p *EncryptedSessionKeyPacket) Type() byte { return 1 }
func (p *EncryptedSessionKeyPacket) EncodeBody() []byte {
	mpi := new(big.Int)
	mpi.SetBytes(p.encryptedSk)
	encryptedMPI := util.EncodeMPI(mpi)

	body := make([]byte, len(encryptedMPI)+10)

	body[0] = 3
	copy(body[1:], p.keyID)
	body[9] = p.keyAlg
	copy(body[10:], encryptedMPI)

	return body
}

func (p *EncryptedSessionKeyPacket) Decrypt(pk *rsa.PrivateKey) (key.SessionKey, error) {
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, pk, p.encryptedSk)
	if err != nil {
		return nil, err
	}

	return key.DecodeSessionKey(decrypted)
}
