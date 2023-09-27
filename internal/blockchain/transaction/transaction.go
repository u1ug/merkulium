package transaction

import (
	"bytes"
	"encoding/json"
	"merkulium/internal/encryption"
	"merkulium/internal/utils"
)

type Transaction struct {
	ID        []byte `json:"id"`
	Sender    []byte `json:"sender"`
	Receiver  []byte `json:"receiver"`
	Amount    uint64 `json:"amount"`
	Fee       uint64 `json:"fee"`
	Hash      []byte `json:"hash"`
	Signature []byte `json:"signature"`
}

func (tx *Transaction) Serialize() ([]byte, error) {
	return json.Marshal(tx)
}

func (tx *Transaction) GetFields() [][]byte {
	return [][]byte{
		tx.ID,
		tx.Sender,
		tx.Receiver,
		utils.Uint64ToBytes(tx.Amount),
		utils.Uint64ToBytes(tx.Fee),
	}
}

func NewTransaction(Sender []byte, Receiver []byte, amount uint64, fee uint64, privateKey []byte) *Transaction {
	var tx = new(Transaction)
	tx.ID = utils.RandomBytes(8)
	tx.Sender = Sender
	tx.Receiver = Receiver
	tx.Amount = amount
	tx.Fee = fee

	txData := tx.GetFields()
	tx.Hash = encryption.BatchHash(txData)
	sign, err := encryption.MultiSign(txData, privateKey)
	if err != nil {
		return nil
	}
	tx.Signature = sign

	return tx
}

func DeserializeTransaction(jsonData []byte) (*Transaction, error) {
	var tx = new(Transaction)
	err := json.Unmarshal(jsonData, &tx)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (tx *Transaction) ValidateID() bool {
	return len(tx.ID) == IdLength
}

func (tx *Transaction) ValidateKeys() bool {
	return encryption.ValidatePublicKey(tx.Sender) != nil && encryption.ValidatePublicKey(tx.Receiver) != nil
}

func (tx *Transaction) ValidateAmount() bool {
	return true
}

func (tx *Transaction) ValidateHash() bool {
	if len(tx.Hash) != HashLength {
		return false
	}
	dataRow := tx.GetFields()
	txHash := encryption.BatchHash(dataRow)
	return bytes.Equal(tx.Hash, txHash)
}

// ValidateSign method requires non-empty and verified hash field before calling.
func (tx *Transaction) ValidateSign() bool {
	return encryption.VerifySign(tx.Sender, tx.Hash, tx.Signature) != nil
}

func (tx *Transaction) Validate() bool {
	if !tx.ValidateID() {
		return false
	}
	if !tx.ValidateKeys() {
		return false
	}
	if !tx.ValidateAmount() {
		return false
	}
	if !tx.ValidateAmount() {
		return false
	}
	if !tx.ValidateHash() {
		return false
	}
	if !tx.ValidateSign() {
		return false
	}
	return true
}
