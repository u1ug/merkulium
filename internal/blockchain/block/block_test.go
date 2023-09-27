package block

import (
	"bytes"
	"merkulium/internal/blockchain/transaction"
	"merkulium/internal/blockchain/user"
	"merkulium/internal/utils"
	"testing"
)

func randomBlock(address []byte) *Block {
	h := Header{
		Version:   1,
		Height:    1,
		Timestamp: 9123912,
		Diff:      10,
		Nonce:     123123,
		Miner:     address,
		Hash:      utils.RandomBytes(32),
		PrevHash:  utils.RandomBytes(32),
		Sign:      nil,
		States:    make(map[string]uint64),
	}
	b := Body{Transactions: make([]transaction.Transaction, 1)}
	b.Transactions[0] = transaction.Transaction{
		ID:        utils.RandomBytes(16),
		Sender:    address,
		Receiver:  []byte("burn"),
		Amount:    15,
		Fee:       0,
		Hash:      utils.RandomBytes(32),
		Signature: utils.RandomBytes(32),
	}

	return &Block{
		header: &h,
		body:   &b,
	}
}

// Create random block and convert in to bytes
func TestBlock_ToBytes(t *testing.T) {
	acc := user.NewUser()
	blk := randomBlock(acc.Address)
	_, err := blk.ToBytes()
	if err != nil {
		panic(err)
	}
}

// Test forging block signature with other user's private key.
func TestBlock_Sign(t *testing.T) {
	acc := user.NewUser()
	fakeAcc := user.NewUser()

	block := randomBlock(acc.Address)

	sign1, err := block.Sign(acc.Password)
	if err != nil {
		t.Fatalf("Failed to sign block with acc: %v", err)
	}
	sign2, err := block.Sign(fakeAcc.Password)
	if err != nil {
		t.Fatalf("Failed to sign block with acc: %v", err)
	}

	if bytes.Equal(sign1, sign2) {
		t.Fatal("signatures are equal")
	}
}
