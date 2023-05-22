package utils

import "encoding/binary"

func Uint64ToBytes(num uint64) []byte {
	bytes := make([]byte, 8)

	binary.BigEndian.PutUint64(bytes, 8)
	return bytes
}
