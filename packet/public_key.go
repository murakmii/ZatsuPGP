package packet

import (
	"github.com/murakmii/ZatsuPGP/key"
	"io"
)

type PublicKeyPacket struct {
	pub *key.PublicKey
}

func DecodePublicKeyPacket(r io.Reader) (*PublicKeyPacket, error) {
	pub, err := key.DecodePublicKey(r)
	if err != nil {
		return nil, err
	}

	return &PublicKeyPacket{pub: pub}, nil
}

func (p *PublicKeyPacket) Type() byte         { return 6 }
func (p *PublicKeyPacket) EncodeBody() []byte { panic("not implemented") }

func (p *PublicKeyPacket) PublicKey() *key.PublicKey {
	return p.pub
}
