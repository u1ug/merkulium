package blockchain

// An Entity is a group of data used as a single object within the blockchain. For example: transaction, block, user.
type Entity interface {
	Serialize() ([]byte, error)
	GetFields() [][]byte
}
