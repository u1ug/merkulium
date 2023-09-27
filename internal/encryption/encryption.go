package encryption

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

//PrivateKey is used only for RSA lib operations such as public key calculation,
//in other cases it is stored as byte array (PrivateKeyBytes).
//For saving key it should be converted to hex format.

// GenerateUserKeys is an implementation of register process. Returns user's public key (login) and private key (password).
func GenerateUserKeys() (publicKeyBytes []byte, privateKeyBytes []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, nil, err
	}
	publicKey := privateKey.PublicKey
	privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyBytes = x509.MarshalPKCS1PublicKey(&publicKey)

	return publicKeyBytes, privateKeyBytes, err
}

// LogIn is a logging in implementation. It calculates user's address by private key.
func LogIn(privateKeyBytes []byte) (publicKeyBytes []byte, err error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.PublicKey
	publicKeyBytes = x509.MarshalPKCS1PublicKey(&publicKey)

	return publicKeyBytes, err
}

func ValidatePublicKey(key []byte) error {
	_, err := x509.ParsePKCS1PublicKey(key)
	return err
}

func SerializeKey(key []byte) ([]byte, error) {
	dst := make([]byte, hex.EncodedLen(len(key)))
	hex.Encode(dst, key)
	return dst, nil
}

func DeserializeKey(keyBytes []byte) (key []byte, err error) {
	dst := make([]byte, hex.DecodedLen(len(keyBytes)))
	_, err = hex.Decode(dst, keyBytes)

	return dst, err
}

func Hash(data []byte) []byte {
	hashWriter := sha256.New()
	hashWriter.Write(data)
	return hashWriter.Sum(nil)
}

func SerializeHash(hash []byte) string {
	return hex.EncodeToString(hash)
}

func DeserializeHash(hashStr string) ([]byte, error) {
	return hex.DecodeString(hashStr)
}

// BatchHash calculates hash for multiple byte slices placed in the batch one.
func BatchHash(data [][]byte) []byte {
	dataRow := bytes.Join(data, nil)
	return Hash(dataRow)
}

// Sign applies a signature function on a given data.
func Sign(data []byte, privateKeyBytes []byte) (sign []byte, err error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	hash := Hash(data)
	sign, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])

	return sign, err
}

// MultiSign is a sign() wrapper for sign([][]byte) calculation.
func MultiSign(data [][]byte, privateKey []byte) (sign []byte, err error) {
	dataRow := bytes.Join(data, nil)
	return Sign(dataRow, privateKey)
}

// VerifySign verifies if data was signed by user with given address.
func VerifySign(addr []byte, hashedData []byte, sign []byte) (err error) {
	key, err := x509.ParsePKCS1PublicKey(addr)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hashedData, sign)
	return err
}
