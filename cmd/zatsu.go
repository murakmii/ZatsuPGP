package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	zatsupgp "github.com/murakmii/ZatsuPGP"
	"io"
	"os"
)

func main() {
	var err error

	switch os.Args[1] {
	case "dump-public-key":
		err = dumpPublicKey()
	case "dump-private-key":
		err = dumpPrivateKey()
	case "encrypt":
		err = encrypt()
	case "decrypt":
		err = decrypt()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to %s: %s\n", os.Args[1], err)
		os.Exit(1)
	}
}

func decodeMessage(path string) (*zatsupgp.Message, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return zatsupgp.DecodeMessage(f)
}

func dumpPublicKey() error {
	msg, err := decodeMessage(os.Args[2])
	if err != nil {
		return err
	}

	pubPkt := msg.PublicKey()
	if pubPkt == nil {
		return errors.New("message has no public key")
	}

	pub := pubPkt.PublicKey()
	fmt.Printf("User ID: %s\n", msg.UserID())
	fmt.Printf("Key ID: %s\n", hex.EncodeToString(pub.KeyID()))
	fmt.Printf("Key length: %d\n", pub.Key().Size()*8)
	fmt.Printf("Created at: %s\n", pub.CreatedAt())

	return nil
}

func dumpPrivateKey() error {
	msg, err := decodeMessage(os.Args[2])
	if err != nil {
		return err
	}

	pk := msg.PrivateKey()
	if pk == nil {
		return errors.New("message has no private key")
	}

	fmt.Printf("User ID: %s\n", msg.UserID())
	fmt.Printf("Key ID: %s\n", hex.EncodeToString(pk.PublicKey().KeyID()))
	fmt.Printf("Key length: %d\n", pk.PublicKey().Key().Size()*8)
	fmt.Printf("S2K: %s\n", pk.S2KFunc())
	fmt.Printf("IV: %s\n", hex.EncodeToString(pk.IV()))

	decTest := "OK"
	if _, err = pk.Decrypt(os.Args[3]); err != nil {
		decTest = err.Error()
	}
	fmt.Printf("Decryption test: %s\n", decTest)

	return nil
}

func encrypt() error {
	msg, err := decodeMessage(os.Args[2])
	if err != nil {
		return err
	}

	pub := msg.PublicKey()
	if pub == nil {
		return errors.New("message has no public key")
	}

	encrypted, err := zatsupgp.Encrypt(pub.PublicKey(), []byte(os.Args[3]), []byte(os.Args[4]))
	if err != nil {
		return err
	}

	return encrypted.EncodeTo(os.Stdout)
}

func decrypt() error {
	encryptedMsg, err := decodeMessage(os.Args[2])
	if err != nil {
		return err
	}

	pkMsg, err := decodeMessage(os.Args[3])
	if err != nil {
		return err
	}

	decryptedMsg, err := encryptedMsg.Decrypt(pkMsg, os.Args[4])
	if err != nil {
		return err
	}

	data := decryptedMsg.LiteralData()
	if data == nil {
		return errors.New("decrypted message has no data")
	}

	fmt.Fprintf(os.Stderr, "Decrypted data: %s(created at: %s)\n", data.Filename(), data.CreatedAt())
	_, err = io.Copy(os.Stdout, bytes.NewReader(data.Data()))

	return err
}
