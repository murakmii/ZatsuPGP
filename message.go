package zatsupgp

import (
	"bytes"
	"errors"
	"github.com/murakmii/ZatsuPGP/key"
	"github.com/murakmii/ZatsuPGP/packet"
	"io"
)

type Message struct {
	packets []packet.Packet
}

func NewMessage(packets []packet.Packet) *Message {
	return &Message{packets: packets}
}

func Encrypt(pub *key.PublicKey, filename, data []byte) (*Message, error) {
	literal, err := packet.BuildLiteralDataPacket('b', filename, data)
	if err != nil {
		return nil, err
	}

	sk, err := key.GenerateSessionKey()
	if err != nil {
		return nil, err
	}

	encrypted, err := packet.BuildEncryptedIntegrityProtectedDataPacket(literal, sk)
	if err != nil {
		return nil, err
	}

	encryptedSk, err := packet.BuildEncryptedSessionKeyPacket(sk, pub)
	if err != nil {
		return nil, err
	}

	return NewMessage([]packet.Packet{encryptedSk, encrypted}), nil
}

func DecodeMessage(r io.Reader) (*Message, error) {
	packets, err := packet.DecodePackets(r)
	if err != nil {
		return nil, err
	}
	return &Message{packets: packets}, nil
}

func (msg *Message) SessionKey() *packet.EncryptedSessionKeyPacket {
	for _, pkt := range msg.packets {
		if sk, ok := pkt.(*packet.EncryptedSessionKeyPacket); ok {
			return sk
		}
	}
	return nil
}

func (msg *Message) PrivateKey() *packet.PrivateKeyPacket {
	for _, pkt := range msg.packets {
		if pk, ok := pkt.(*packet.PrivateKeyPacket); ok {
			return pk
		}
	}
	return nil
}

func (msg *Message) PublicKey() *packet.PublicKeyPacket {
	for _, pkt := range msg.packets {
		if pub, ok := pkt.(*packet.PublicKeyPacket); ok {
			return pub
		}
	}
	return nil
}

func (msg *Message) LiteralData() *packet.LiteralDataPacket {
	for _, pkt := range msg.packets {
		if literal, ok := pkt.(*packet.LiteralDataPacket); ok {
			return literal
		}
	}
	return nil
}

func (msg *Message) UserID() *packet.UserIDPacket {
	for _, pkt := range msg.packets {
		if uid, ok := pkt.(*packet.UserIDPacket); ok {
			return uid
		}
	}
	return nil
}

func (msg *Message) EncryptedData() *packet.EncryptedIntegrityProtectedDataPacket {
	for _, pkt := range msg.packets {
		if enc, ok := pkt.(*packet.EncryptedIntegrityProtectedDataPacket); ok {
			return enc
		}
	}
	return nil
}

func (msg *Message) Decrypt(pkMsg *Message, passphrase string) (*Message, error) {
	pkPkt := pkMsg.PrivateKey()
	if pkPkt == nil {
		return nil, errors.New("no private key found")
	}
	pk, err := pkPkt.Decrypt(passphrase)
	if err != nil {
		return nil, err
	}

	skPkt := msg.SessionKey()
	if skPkt == nil {
		return nil, errors.New("no session key found")
	}
	sk, err := skPkt.Decrypt(pk)
	if err != nil {
		return nil, err
	}

	encrypted := msg.EncryptedData()
	if encrypted == nil {
		return nil, errors.New("no encrypted data found")
	}

	packets, err := encrypted.Decrypt(sk)
	if err != nil {
		return nil, err
	}

	return &Message{packets: packets}, nil
}

func (msg *Message) EncodeTo(w io.Writer) error {
	for _, pkt := range msg.packets {
		if _, err := io.Copy(w, bytes.NewReader(packet.EncodePacket(pkt))); err != nil {
			return err
		}
	}
	return nil
}
