package encryption

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
)

type testEntity struct {
	Field1 []byte
	Field2 []byte
}

func (t testEntity) Serialize() ([]byte, error) {
	return json.Marshal(t)
}

func (t testEntity) GetFields() [][]byte {
	return [][]byte{
		t.Field1,
		t.Field2,
	}
}

func newTestEntity() *testEntity {
	field1 := make([]byte, 8)
	field2 := make([]byte, 8)
	_, err := rand.Read(field1)
	if err != nil {
		panic(err)
	}
	_, err = rand.Read(field2)
	if err != nil {
		panic(err)
	}

	return &testEntity{
		Field1: field1,
		Field2: field2,
	}
}

func TestNewUser(t *testing.T) {
	fmt.Println("Generating a new user")
	address, password, err := GenerateUserKeys()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated user with address: %v and password %v\n", string(address), string(password))
}

func TestSerializeKeys(t *testing.T) {
	fmt.Println("Generating a new user with readable data")
	address, password, err := GenerateUserKeys()
	if err != nil {
		panic(err)
	}
	addressBase64, err := SerializeKey(address)
	if err != nil {
		panic(err)
	}
	passwordBase64, err := SerializeKey(password)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Address: %v\nPassword: %v\n", string(addressBase64), string(passwordBase64))
}

func TestLogIn(t *testing.T) {
	addr, key, err := GenerateUserKeys()
	if err != nil {
		panic(err)
	}

	addr1, err := LogIn(key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("generated key:%v\ncalculated key%v\n", addr, addr1)
	if !bytes.Equal(addr, addr1) {
		panic("keys are not matching")
	}
}

// TestSign1 tests signature verification on valid data.
func TestSign1(t *testing.T) {
	addr, key, err := GenerateUserKeys()
	if err != nil {
		panic(err)
	}

	testStruct := newTestEntity()
	dataHash := BatchHash(testStruct.GetFields())
	dataSign, err := MultiSign(testStruct.GetFields(), key)
	if err != nil {
		panic(err)
	}

	err = VerifySign(addr, dataHash, dataSign)
	if err != nil {
		panic("invalid signature")
	}
}

// TestSign2 tests signature address forgery.
func TestSign2(t *testing.T) {
	_, key, err := GenerateUserKeys()
	if err != nil {
		panic(err)
	}
	fakeAddr, _, err := GenerateUserKeys()
	if err != nil {
		panic(err)
	}

	testStruct := newTestEntity()
	dataHash := BatchHash(testStruct.GetFields())
	dataSign, err := MultiSign(testStruct.GetFields(), key)
	if err != nil {
		panic(err)
	}

	err = VerifySign(fakeAddr, dataHash, dataSign)
	if err == nil {
		println("verification failed")
	}
}

func TestPOW(t *testing.T) {
	data := []byte("YDRN I am the test data")
	target := big.NewInt(100)
	nonce := POW(data, target)
	fmt.Println("nonce: ", nonce)
}
