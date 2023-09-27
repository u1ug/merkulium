package block

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"merkulium/internal/blockchain/transaction"
	"merkulium/internal/encryption"
)

type Header struct {
	Version   uint32            // Merkulium protocol version
	Height    uint64            // Block number
	Timestamp int64             // Unix time when block was mined
	Diff      uint64            // Block PoW target difficulty
	Nonce     int64             // PoW puzzle solution
	Miner     []byte            // Block issuer public key
	Hash      []byte            // Block hash
	PrevHash  []byte            // Previous block hash
	Sign      []byte            // Block signature applied by Miner
	States    map[string]uint64 // Map with current block transaction participants balances
}

type Body struct {
	Transactions []transaction.Transaction
}

type Block struct {
	header *Header
	body   *Body
}

// ToBytes packs block to byte slice.
func (b *Block) ToBytes() ([]byte, error) {
	fields := new(bytes.Buffer)
	if err := binary.Write(fields, binary.LittleEndian, b.header.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(fields, binary.LittleEndian, b.header.Height); err != nil {
		return nil, err
	}
	if err := binary.Write(fields, binary.LittleEndian, b.header.Timestamp); err != nil {
		return nil, err
	}
	if err := binary.Write(fields, binary.LittleEndian, b.header.Diff); err != nil {
		return nil, err
	}
	if err := binary.Write(fields, binary.LittleEndian, b.header.Nonce); err != nil {
		return nil, err
	}
	if err := binary.Write(fields, binary.LittleEndian, b.header.Miner); err != nil {
		return nil, err
	}
	if err := binary.Write(fields, binary.LittleEndian, b.header.Hash); err != nil {
		return nil, err
	}
	if err := binary.Write(fields, binary.LittleEndian, b.header.PrevHash); err != nil {
		return nil, err
	}
	if err := binary.Write(fields, binary.LittleEndian, b.header.Sign); err != nil {
		return nil, err
	}
	statesJSON, err := json.Marshal(b.header.Sign)
	if err != nil {
		return nil, err
	}
	if err = binary.Write(fields, binary.LittleEndian, statesJSON); err != nil {
		return nil, err
	}
	return fields.Bytes(), nil
}

func (b *Block) Sign(privateKey []byte) ([]byte, error) {
	blockBytes, err := b.ToBytes()
	if err != nil {
		return nil, err
	}
	return encryption.Sign(blockBytes, privateKey)
}

func (b *Block) Hash() ([]byte, error) {
	blockBytes, err := b.ToBytes()
	if err != nil {
		return nil, err
	}
	return encryption.Hash(blockBytes), nil
}
