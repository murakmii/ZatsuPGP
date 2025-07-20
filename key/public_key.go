package key

import (
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"github.com/murakmii/ZatsuPGP/util"
	"io"
	"math/big"
	"time"
)

type PublicKey struct {
	alg       byte
	key       *rsa.PublicKey
	createdAt time.Time
}

func DecodePublicKey(r io.Reader) (*PublicKey, error) {
	metadata, err := util.ReadBytes(r, 6)
	if err != nil {
		return nil, err
	}
	if metadata[0] != 4 || metadata[5] != 1 {
		return nil, errors.New("public key packet must be v4 and RSA")
	}

	n, err := util.DecodeMPI(r)
	if err != nil {
		return nil, err
	}

	e, err := util.DecodeMPI(r)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		metadata[5],
		&rsa.PublicKey{N: n, E: int(e.Int64())},
		time.Unix(int64(binary.BigEndian.Uint32(metadata[1:])), 0),
	}, nil
}

func (pub *PublicKey) Alg() byte            { return pub.alg }
func (pub *PublicKey) Key() *rsa.PublicKey  { return pub.key }
func (pub *PublicKey) CreatedAt() time.Time { return pub.createdAt }

func (pub *PublicKey) KeyID() []byte {
	n := util.EncodeMPI(pub.key.N)
	e := util.EncodeMPI(big.NewInt(int64(pub.key.E)))

	input := make([]byte, len(n)+len(e)+9)
	input[0] = 0x99
	binary.BigEndian.PutUint16(input[1:], uint16(len(input)-3))
	input[3] = 0x04
	binary.BigEndian.PutUint32(input[4:], uint32(pub.createdAt.Unix()))
	input[8] = pub.alg

	copy(input[9:], n)
	copy(input[len(n)+9:], e)

	fingerprint := sha1.Sum(input)
	return fingerprint[12:20]
}
