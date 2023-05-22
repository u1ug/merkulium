package blockchain

import (
	"encoding/json"
	"merkulium/internal/encryption"
)

type User struct {
	Address  []byte
	Password []byte
}

func (u User) Serialize() ([]byte, error) {
	return json.Marshal(u)
}

func (u User) GetFields() [][]byte {
	//TODO implement me
	panic("implement me")
}

func NewUser(address []byte, password []byte) *User {
	address, password, err := encryption.GenerateUserKeys()
	if err != nil {
		panic(err)
	}
	return &User{Address: address, Password: password}
}