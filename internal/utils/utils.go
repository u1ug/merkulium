package utils

import (
	"crypto/rand"
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
