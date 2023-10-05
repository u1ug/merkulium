package encryption

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"merkulium/internal/utils"
)

// POW computes proof-of-work puzzle and returns first solution found.
func POW(data []byte, diff uint) uint64 {
	var (
		nonce   uint64
		hashInt big.Int
	)
	target := new(big.Int).Lsh(big.NewInt(1), 256-diff)
	nonceBytes := make([]byte, 8)
	for {
		binary.LittleEndian.PutUint64(nonceBytes, nonce)
		hash := append(data, nonceBytes...)
		hash = Hash(hash)
		fmt.Printf("\rmining: %v, nonce %d", utils.ToBase64(hash), nonce)
		hashInt.SetBytes(hash)
		if hashInt.Cmp(target) == -1 {
			return nonce
		}
		nonce++
	}
}
