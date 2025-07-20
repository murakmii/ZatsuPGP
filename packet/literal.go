package packet

import (
	"encoding/binary"
	"errors"
	"github.com/murakmii/ZatsuPGP/util"
	"io"
	"time"
)

type LiteralDataPacket struct {
	format    byte
	filename  []byte
	createdAt time.Time
	data      []byte
}

func BuildLiteralDataPacket(format byte, filename []byte, data []byte) (*LiteralDataPacket, error) {
	if len(filename) > 255 {
		return nil, errors.New("filename too long")
	}

	return &LiteralDataPacket{
		format:    format,
		filename:  filename,
		createdAt: time.Now(),
		data:      data,
	}, nil
}

func DecodeLiteralDataPacket(r io.Reader) (*LiteralDataPacket, error) {
	formatAndNameLen, err := util.ReadBytes(r, 2)
	if err != nil {
		return nil, err
	}

	filename, err := util.ReadBytes(r, int(formatAndNameLen[1]))
	if err != nil {
		return nil, err
	}

	timeAndData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(timeAndData) < 4 {
		return nil, errors.New("invalid literal data packet(no time info)")
	}

	return &LiteralDataPacket{
		format:    formatAndNameLen[0],
		filename:  filename,
		createdAt: time.Unix(int64(binary.BigEndian.Uint32(timeAndData)), 0),
		data:      timeAndData[4:],
	}, nil
}

func (p *LiteralDataPacket) Type() byte { return 11 }

func (p *LiteralDataPacket) EncodeBody() []byte {
	body := make([]byte, len(p.filename)+len(p.data)+6)
	body[0] = p.format
	body[1] = byte(len(p.filename))

	copy(body[2:], p.filename)
	afterFilename := body[len(p.filename)+2:]

	binary.BigEndian.PutUint32(afterFilename, uint32(p.createdAt.Unix()))
	copy(afterFilename[4:], p.data)

	return body
}

func (p *LiteralDataPacket) Filename() []byte     { return p.filename }
func (p *LiteralDataPacket) CreatedAt() time.Time { return p.createdAt }
func (p *LiteralDataPacket) Data() []byte         { return p.data }
