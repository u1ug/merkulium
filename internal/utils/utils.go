package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
)

func Uint64ToBytes(num uint64) []byte {
	bytes := make([]byte, 8)

	binary.BigEndian.PutUint64(bytes, 8)
	return bytes
}

func RandomBytes(length uint) []byte {
	randomSequence := make([]byte, length)

	_, err := rand.Read(randomSequence)
	if err != nil {
		return nil
	}

	return randomSequence
}

func ToBase64(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}
