package blockchain

import (
	"math/rand"
	"merkulium/internal/encryption"
	"merkulium/internal/utils"
	"reflect"
	"testing"
)

func randomBlock() *Block {
	addr, key, err := encryption.GenerateUserKeys()
	if err != nil {
		panic(err)
	}
	block := &Block{
		Height:       uint64(rand.Uint32())<<32 + uint64(rand.Uint32()),
		Diff:         uint64(rand.Uint32())<<32 + uint64(rand.Uint32()),
		Transactions: nil,
		Mapping:      nil,
		Miner:        addr,
		Hash:         nil,
		PrevHash:     utils.RandomBytes(32),
		Sign:         nil,
	}
	block.Hash = block.hash()
	block.Sign, err = block.sign(key)
	if err != nil {
		panic(err)
	}
	return block
}

func TestBlockSerialization(t *testing.T) {
	block := randomBlock()
	serBlock, err := block.Serialize()
	if err != nil {
		panic(err)
	}
	block1, err := DeserializeBlock(serBlock)
	if err != nil {
		panic(err)
	}

	if !reflect.DeepEqual(block, block1) {
		panic("blocks are not match")
	}
}

func TestTxSerialization(t *testing.T) {
	addr, key, err := encryption.GenerateUserKeys()
	if err != nil {
		panic(err)
	}
	tx := NewTransaction(addr, utils.RandomBytes(74), 10, 1, key)
	serTx, err := tx.Serialize()
	if err != nil {
		panic(err)
	}
	tx1, err := DeserializeTransaction(serTx)
	if err != nil {
		panic(err)
	}

	if !reflect.DeepEqual(tx, tx1) {
		panic("transactions are not match")
	}
}
