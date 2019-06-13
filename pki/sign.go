package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
	"log"
)

// Sign - receives a messsage (limited to 250char)
// it sha256 hashes and then rsa signs it, and returns a base64 encoded signature
func Sign(message string) (string, error) {

	// TODO check length on string
	// Sign
	var h hash.Hash
	h = sha256.New()

	io.WriteString(h, message)
	signhash := h.Sum(nil)

	rsaKey, err := loadPrivateKeyFromFile()
	if err != nil {
		return "", err
	}
	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, signhash)
	if err != nil {
		log.Fatal(err)
		return "", err
	}

	sEnc := base64.StdEncoding.EncodeToString(rsaSignature)
	return sEnc, nil
}

// Verify -
func Verify(message, b64signature string) error {
	signature, err := base64.StdEncoding.DecodeString(b64signature)
	if err != nil {
		return err
	}

	h := sha256.New()
	io.WriteString(h, message)
	d := h.Sum(nil)

	rsaKey, err := loadPublicKeyFromFile()
	if err != nil {
		log.Fatalf("err getting public key %s\n", err)
	}
	e := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, d, signature)
	return e
}

// CreateRSA - just a test func. Remove after done
func CreateRSA() {
	err := createNewRsaSet("test1")
	if err != nil {
		log.Fatal("error creating public/private key set")
	}
}
