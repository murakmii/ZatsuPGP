package s2k

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/murakmii/ZatsuPGP/util"
	"io"
)

type (
	Func interface {
		DeriveKey([]byte, int) []byte
		String() string
	}

	iterAndSalted struct {
		salt  []byte
		count int
	}
)

func DecodeS2KSpecifier(r io.Reader) (Func, error) {
	if specifier, err := util.ReadInt(r, 1); err != nil {
		return nil, err
	} else if specifier != 3 {
		return nil, errors.New("S2K specifier must be 3(iter+salt)")
	}

	metadata, err := util.ReadBytes(r, 10)
	if err != nil {
		return nil, err
	}
	if metadata[0] != 2 {
		return nil, fmt.Errorf("hash algorithm of S2K must be SHA-1")
	}

	return &iterAndSalted{
		salt:  metadata[1:9],
		count: (16 + int(metadata[9]&15)) << (uint32(metadata[9]>>4) + 6),
	}, nil
}

func (ias *iterAndSalted) DeriveKey(password []byte, keySize int) []byte {
	input := make([]byte, len(password)+len(ias.salt))
	copy(input, ias.salt)
	copy(input[len(ias.salt):], password)

	dk := make([]byte, keySize)

	hasher := sha1.New()
	for i, offset := 0, 0; offset < keySize; i++ {
		hasher.Reset()
		hasher.Write(make([]byte, i))

		for remain := ias.count; remain > 0; {
			remain -= len(input)
			if remain >= 0 {
				hasher.Write(input)
			} else {
				hasher.Write(input[:len(input)+remain])
			}
		}

		offset += copy(dk[offset:], hasher.Sum(nil))
	}

	return dk
}

func (ias *iterAndSalted) String() string {
	return fmt.Sprintf("iter+salt(%d:%s)", ias.count, hex.EncodeToString(ias.salt))
}
