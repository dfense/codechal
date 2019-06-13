package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
)

// load public key
// load private key

const (
	privateFile = "./id_rsa_test"
	publicFile  = "./id_rsa_test.pub"
)

// make this a default, but override-able
var bitSize = 4096

// privateKey, err := generatePrivateRSAKey(bitSize)
// if err != nil {
// 	log.Fatal(err.Error())
// }

// privateKeyPEM := encodePrivateRSAKeyToPEM(privateKey)
// err = writeKeyToFile(privateKeyPEM, savePrivateFileTo)
// if err != nil {
// 	log.Fatal(err.Error())
// }

// publicKey := privateKey.PublicKey
// publicKeyBytes, err := asn1.Marshal(publicKey)
// publicKeyPEM := encodePublicRSAKeyToPEM(publicKeyBytes)
// err = writeKeyToFile([]byte(publicKeyPEM), savePublicFileTo)
// if err != nil {
// 	log.Fatal(err.Error())
// }

// generatePrivateRSAKey - creates RSA Private Key of specified byte size
func generatePrivateRSAKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateRSAKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	asn1Bytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privateBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   asn1Bytes,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privateBlock)

	return privatePEM
}

func encodePublicRSAKeyToPEM(publicKey []byte) []byte {

	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey,
	}

	publicPEM := pem.EncodeToMemory(publicBlock)
	return publicPEM
}

// writePemToFile writes keys to a file
// func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
// 	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
// 	if err != nil {
// 		return err
// 	}

// 	log.Printf("Key saved to: %s", saveFileTo)
// 	return nil
// }

func loadSigner() {

	loadPrivateKeyFromFile()
}

// loadPrivateKeyFromFile - look for a private key PEM formatted file
// if private key file does not exists, create a new public/private key set
// then read and parse the key out and return,
func loadPrivateKeyFromFile1() (*rsa.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(privateFile)
	if err != nil {
		return nil, err
	}

	// looking for single PEM block only. remainder not important now
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("no private key found in bytestream")
	}

	switch pemBlock.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return rsa, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", pemBlock.Type)
	}

}

// loadPublicKeyFromFile - look for a public key PEM formatted file
// if public key file does not exists, create a new public/private key set
// then read and parse the key out and return,
func loadPublicKeyFromFile1() (*rsa.PublicKey, error) {
	pemBytes, err := ioutil.ReadFile(publicFile)
	if err != nil {
		return nil, err
	}

	// looking for single PEM block only. remainder not important now
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("no public key found in bytestream")
	}

	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	switch pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("pub is of type RSA:", pub)
		goodKey := pub.(*rsa.PublicKey)
		return goodKey, nil
	default:
		panic("unknown type of public key")
	}

}

// extractPrivateKey - parses a PEM encoded bytestream looking to extract a private key
func parsePrivateKey(pemBytes []byte) (*crypto.Signer, error) {

	// looking for single PEM block only. remainder not important now
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("no private key found in bytestream")
	}

	var rawkey interface{}
	switch pemBlock.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("unsupported key type %q", pemBlock.Type)
	}

	signer, err := createSignerFromKey(rawkey)
	if err != nil {
		return nil, err
	}
	return &signer, nil
}

// createSignerFromKey -
func createSignerFromKey(k interface{}) (crypto.Signer, error) {

	// rsaKey := rsa.PrivateKey{}
	// return &rsaKey, nil
	// setup block for possible other possible key types
	switch k.(type) {
	case *rsa.PrivateKey:

		privateKey := k.(*rsa.PrivateKey)
		return privateKey, nil

	default:
		return nil, fmt.Errorf("unsupported key type %T", k)
	}

}

// createNewRsaSet - generate a new RSA public and private key
// baseName string - the prefix of the filename used to store
func createNewRsaSet(baseName string) error {

	privateKey, err := generatePrivateRSAKey(bitSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	privateKeyPEM := encodePrivateRSAKeyToPEM(privateKey)
	err = writeKeyToFile(privateKeyPEM, privateFile)
	if err != nil {
		return err
	}

	publicKey := privateKey.PublicKey
	publicKeyBytes, err := asn1.Marshal(publicKey)
	publicKeyPEM := encodePublicRSAKeyToPEM(publicKeyBytes)
	err = writeKeyToFile([]byte(publicKeyPEM), publicFile)
	if err != nil {
		return err
	}

	return nil

}
