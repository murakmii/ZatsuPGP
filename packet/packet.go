package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/murakmii/ZatsuPGP/util"
	"io"
)

type (
	Packet interface {
		Type() byte
		EncodeBody() []byte
	}

	UnsupportedPacket struct {
		typ  byte
		body []byte
	}
)

var NoMorePacket = errors.New("no more packet")

func NewUnsupportedPacket(typ byte, body []byte) *UnsupportedPacket {
	return &UnsupportedPacket{typ: typ, body: body}
}

func (p *UnsupportedPacket) Type() byte         { return p.typ }
func (p *UnsupportedPacket) EncodeBody() []byte { return p.body }

func DecodePackets(r io.Reader) ([]Packet, error) {
	packets := make([]Packet, 0)
	for {
		pkt, err := DecodePacket(r)
		if err != nil {
			if errors.Is(err, NoMorePacket) {
				return packets, nil
			}
			return nil, err
		}

		packets = append(packets, pkt)
	}
}

func DecodePacket(r io.Reader) (Packet, error) {
	head, err := util.ReadBytes(r, 1)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, NoMorePacket
		}
		return nil, err
	}

	var tag byte
	var body []byte

	if (head[0] & 0x40) > 0 {
		tag = head[0] & 0x3F
		body, err = decodeNewFormatPacket(r)
	} else {
		tag = (head[0] >> 2) & 0x0F
		body, err = decodeOldFormatPacket(r, head[0]&0x03)
	}
	if err != nil {
		return nil, err
	}

	var packet Packet
	switch tag {
	case 1:
		packet, err = DecodeEncryptedSessionKeyPacket(bytes.NewReader(body))
	case 5:
		packet, err = DecodePrivateKeyPacket(bytes.NewReader(body))
	case 6:
		packet, err = DecodePublicKeyPacket(bytes.NewReader(body))
	case 11:
		packet, err = DecodeLiteralDataPacket(bytes.NewReader(body))
	case 13:
		packet = NewUserIDPacket(body)
	case 18:
		packet, err = DecodeEncryptedIntegrityProtectedDataPacket(bytes.NewReader(body))
	default:
		packet = NewUnsupportedPacket(tag, body)
	}

	return packet, err
}

func decodeNewFormatPacket(r io.Reader) ([]byte, error) {
	octet1, err := util.ReadInt(r, 1)
	if err != nil {
		return nil, err
	}

	if octet1 < 192 {
		return util.ReadBytes(r, int(octet1))

	} else if octet1 == 255 {
		lenOctets, err := util.ReadBytes(r, 4)
		if err != nil {
			return nil, err
		}
		return util.ReadBytes(r, int(binary.BigEndian.Uint32(lenOctets)))

	} else {
		lenOctets, err := util.ReadBytes(r, 2)
		if err != nil {
			return nil, err
		}
		return util.ReadBytes(r, int((uint32(lenOctets[0]-192)<<8)+uint32(lenOctets[1])+192))
	}
}

func decodeOldFormatPacket(r io.Reader, lenType byte) ([]byte, error) {
	if lenType == 3 {
		return io.ReadAll(r)
	}

	lenOctets, err := util.ReadBytes(r, 1<<lenType)
	if err != nil {
		return nil, err
	}

	var bodyLen uint32
	for _, octet := range lenOctets {
		bodyLen = (bodyLen << 8) | uint32(octet)
	}

	return util.ReadBytes(r, int(bodyLen))
}

func EncodePacket(p Packet) []byte {
	body := p.EncodeBody()

	encoded := make([]byte, len(body)+6)
	encoded[0] = 0xC0 | byte(p.Type())
	encoded[1] = 0xFF

	binary.BigEndian.PutUint32(encoded[2:], uint32(len(body)))
	copy(encoded[6:], body)

	return encoded
}
