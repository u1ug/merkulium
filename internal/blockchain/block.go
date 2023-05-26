package blockchain

import (
	"bytes"
	"encoding/json"
	"merkulium/internal/encryption"
)

type Block struct {
	Height       uint64
	Diff         uint64
	Transactions []Transaction
	Mapping      map[string]uint64
	Miner        []byte
	Hash         []byte
	PrevHash     []byte
	Sign         []byte
}

func (b Block) hash() []byte {
	fields := b.GetFields()
	return encryption.MultiHash(fields)
}

func (b Block) sign(privateKey []byte) ([]byte, error) {
	fields := b.GetFields()
	return encryption.MultiSign(fields, privateKey)
}

// Block serialization: block -> jsonBlock -> bytes
// Block deserialization: bytes -> jsonBlock -> block
// JSONBlock is needed to convert Block byte fields to string format

func (b Block) Serialize() ([]byte, error) {
	jsonBlock := &JSONBLock{
		b.Height,
		b.Diff,
		b.Transactions,
		b.Mapping,
		encryption.SerializeHash(b.Miner),
		encryption.SerializeHash(b.Hash),
		encryption.SerializeHash(b.PrevHash),
		encryption.SerializeHash(b.Sign),
	}
	return jsonBlock.Serialize()
}

func (b Block) GetFields() [][]byte {
	transactions := make([][]byte, len(b.Transactions))
	for i, tx := range b.Transactions {
		transactions[i] = bytes.Join(tx.GetFields(), nil)
	}
	return transactions
}

type JSONBLock struct {
	Height       uint64            `json:"height"`
	Diff         uint64            `json:"diff"`
	Transactions []Transaction     `json:"transactions"`
	Mapping      map[string]uint64 `json:"mapping"`
	Miner        string            `json:"miner"`
	Hash         string            `json:"hash"`
	PrevHash     string            `json:"prevHash"`
	Sign         string            `json:"sign"`
}

func (J JSONBLock) Serialize() ([]byte, error) {
	return json.Marshal(J)
}

func DeserializeBlock(data []byte) (*Block, error) {
	var (
		jsonBlock = new(JSONBLock)
		err       error
	)
	err = json.Unmarshal(data, &jsonBlock)
	if err != nil {
		return nil, err
	}

	miner, err := encryption.DeserializeHash(jsonBlock.Miner)
	if err != nil {
		return nil, err
	}
	hash, err := encryption.DeserializeHash(jsonBlock.Hash)
	if err != nil {
		return nil, err
	}
	prevHash, err := encryption.DeserializeHash(jsonBlock.PrevHash)
	if err != nil {
		return nil, err
	}
	sign, err := encryption.DeserializeHash(jsonBlock.Sign)
	if err != nil {
		return nil, err
	}
	return &Block{
		Height:       jsonBlock.Height,
		Diff:         jsonBlock.Diff,
		Transactions: jsonBlock.Transactions,
		Mapping:      jsonBlock.Mapping,
		Miner:        miner,
		Hash:         hash,
		PrevHash:     prevHash,
		Sign:         sign,
	}, nil
}
