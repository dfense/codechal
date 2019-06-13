package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"

	"github.com/dfense/model"
	"github.com/dfense/util"
)

const (
	//perms for keys
	fileMode          = 0600
	privateRsaKeyFile = "./id_rsa_test"
	publicRsaKeyFile  = "./id_rsa_test.pub"
)

var (
	rsaKeySize  = 2048
	rsaKeySizes = []int{1024, 2048, 4096}
)

// SetRsaKeySize - sets the size that genRsaKeys will use
// if a new keyset is created
func SetRsaKeySize(keySize int) error {
	if !util.ContainsInt(rsaKeySizes, keySize) {
		return errors.New("invalid key size. use 1024, 2048, or 4096")
	}
	rsaKeySize = keySize
	return nil
}

// ResetKeys - deletes keys and forces a new rsa keyset to be generated
func ResetKeys() {
	err := deleteKeyFiles(privateRsaKeyFile, publicRsaKeyFile)
	log.Println(err)
}

// PrepareResult - pass back fields that were signed, and
// let keyFactory fill in the public key
func PrepareResult(message, signature string) (*model.KeyResponse, error) {

	if !fileExists(publicRsaKeyFile) {
		return nil, errors.New("public rsa key file does not exist")
	}
	pemBytes, err := ioutil.ReadFile(publicRsaKeyFile)
	if err != nil {
		return nil, err
	}

	return &model.KeyResponse{
		Message:   message,
		Signature: signature,
		Pubkey:    string(pemBytes),
	}, nil

}

// rsaKeyGen - generate an RSA private key.
// Return pointers to the private and public array
func genRsaKeys(bitSize int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, bitSize)
	return privkey, &privkey.PublicKey
}

// createPrivateRsaPEM - converts a private key to ASN.1 DER encoded slice
func createPrivateRsaPEM(privateKey *rsa.PrivateKey) []byte {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return privateKeyPEM
}

// createPublicRsaPEM - converts a public key to ASN.1 DER encoded slice
// can expand to detect nultiple type of formats including ECDSA and more...
func createPublicRsaPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return publicKeyPEM, nil
}

// extractPrivateRsaKeyFromPEM - extracts RsaKey as slice from ASN.1 encoded slice
func extractPrivateRsaKeyFromPEM(data []byte) (*rsa.PrivateKey, error) {

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func extractPublicRsaKeyFromPEM(data []byte) (*rsa.PublicKey, error) {

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("key type is not RSA")
	}
}

// loadPrivateKeyFromFile - if file exist, loads PEM, extracts key
// and returns *rsa.PrivateKey. If file doesn't exist, it creates a new pair.
// if exist, but can't parse, returns error
func loadPrivateKeyFromFile() (*rsa.PrivateKey, error) {
	if !fileExists(privateRsaKeyFile) {
		createAndSaveRsaKeys()
	}
	pemBytes, err := ioutil.ReadFile(privateRsaKeyFile)
	if err != nil {
		return nil, err
	}

	privateKey, err := extractPrivateRsaKeyFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func loadPublicKeyFromFile() (*rsa.PublicKey, error) {
	if !fileExists(publicRsaKeyFile) {
		createAndSaveRsaKeys()
	}
	pemBytes, err := ioutil.ReadFile(publicRsaKeyFile)
	if err != nil {
		return nil, err
	}

	publicKey, err := extractPublicRsaKeyFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

// func saveKeyFiles()

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("new key saved to: %s", saveFileTo)
	return nil
}

// deleteKeyFiles - convenience method to clear out and allow
// new files to be generated on next call into factory
func deleteKeyFiles(privateRsaKeyFile, publicRsaKeyFile string) error {
	if err := os.Remove(privateRsaKeyFile); err != nil {
		return err
	}
	if err := os.Remove(publicRsaKeyFile); err != nil {
		return err
	}
	return nil
}

// Or as a kind user on reddit refactored:
func checkErr(err error) {
	if err != nil {
		log.Fatal("ERROR:", err)
	}
}

// createAndSaveRsaKeys
func createAndSaveRsaKeys() error {

	// TODO mutex lock, in case 2 calls simultaneous, but
	// overengineered if we are going to run a single docker run for challenge
	privateKey, publicKey := genRsaKeys(rsaKeySize)

	privateRsaPEM := createPrivateRsaPEM(privateKey)
	if err := writeKeyToFile(privateRsaPEM, privateRsaKeyFile); err != nil {
		return err
	}

	publicRsaPEM, err := createPublicRsaPEM(publicKey)
	if err != nil {
		return err
	}
	if err := writeKeyToFile(publicRsaPEM, publicRsaKeyFile); err != nil {
		return err
	}
	return nil
}

// fileExists - convenience method if file exists
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
