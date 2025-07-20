package util

import (
	"encoding/binary"
	"io"
	"math/big"
)

func ReadBytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func ReadInt(r io.Reader, size int) (uint32, error) {
	octets, err := ReadBytes(r, size)
	if err != nil {
		return 0, err
	}

	var i uint32
	for _, octet := range octets {
		i = (i << 8) | uint32(octet)
	}
	
	return i, nil
}

func DecodeMPI(r io.Reader) (*big.Int, error) {
	bits, err := ReadInt(r, 2)
	if err != nil {
		return nil, err
	}

	octets, err := ReadBytes(r, (int(bits)+7)/8)
	if err != nil {
		return nil, err
	}

	mpi := new(big.Int)
	mpi.SetBytes(octets)
	return mpi, nil
}

func EncodeMPI(mpi *big.Int) []byte {
	bytes := mpi.Bytes()
	encoded := make([]byte, len(bytes)+2)

	binary.BigEndian.PutUint16(encoded, uint16(mpi.BitLen()))
	copy(encoded[2:], bytes)

	return encoded
}
