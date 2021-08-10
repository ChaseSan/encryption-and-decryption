package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"io"
)

func main() {
	uu := Uuid()
	fmt.Printf("Plain text: %s\n", uu)
	encryptedText := cryptoEn(uu)
	cryptoDe(encryptedText)
}

// Uuid generate uuid version 4.
func Uuid() (uu string) {
	u, _ := uuid.NewRandom()
	uu = u.String()
	return
}

func cryptoEn(text string) string {
	plainText := []byte(text)
	cipherText, _ := createIv(plainText)
	block, _ := createBlock()

	encryptedText := doEncrypt(block, cipherText, plainText)
	fmt.Printf("EncryptedText text: %s\n", encryptedText)

	return encryptedText
}

func cryptoDe(encryptedText string) []byte {
	block, _ := createBlock()

	decodedText, _ := hex.DecodeString(encryptedText)
	decryptedText := doDecrypt(block, decodedText)
	fmt.Printf("Decrypted text: %s\n", string(decryptedText))

	return decryptedText
}

func createBlock() (block cipher.Block, err error) {
	key := []byte("00000000000000000000000000000000")
	block, err = aes.NewCipher(key)
	return
}

func createIv(plainText []byte) (cipherText []byte, err error) {
	cipherText = make([]byte, aes.BlockSize+len(plainText))
	if _, err = io.ReadFull(rand.Reader, cipherText[:aes.BlockSize]); err != nil {
		return
	}
	return
}

func doEncrypt(block cipher.Block, cipherText []byte, plainText []byte) string {
	encryptStream := cipher.NewCTR(block, cipherText[:aes.BlockSize])
	encryptStream.XORKeyStream(cipherText[aes.BlockSize:], plainText)
	return hex.EncodeToString(cipherText)
}

func doDecrypt(block cipher.Block, cipherText []byte) []byte {
	decryptedText := make([]byte, len(cipherText[aes.BlockSize:]))
	decryptStream := cipher.NewCTR(block, cipherText[:aes.BlockSize])
	decryptStream.XORKeyStream(decryptedText, cipherText[aes.BlockSize:])
	return decryptedText
}
