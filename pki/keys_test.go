package pki

import (
	"testing"

	"github.com/dfense/codechal/util"
)

func TestCreateAndPEM(t *testing.T) {

	keySize := 2048
	privateKey, publicKey := genRsaKeys(keySize)

	// transcode the keys to pem slice
	privateKeyPEM := createPrivateRsaPEM(privateKey)
	publicKeyPEM, err := createPublicRsaPEM(publicKey)
	if err != nil {
		t.Error(err)
	}

	privateKeyExtract, err := extractPrivateRsaKeyFromPEM(privateKeyPEM)
	if err != nil {
		t.Error(err)
	}
	err = privateKeyExtract.Validate()
	if err != nil {
		t.Error(err)
	}
	_, err = extractPublicRsaKeyFromPEM(publicKeyPEM)
	if err != nil {
		t.Error(err)
	}
}

func TestSaveAndDeleteKeyFiles(t *testing.T) {

	// will create new files if not on disk
	privateKey, err := loadPrivateKeyFromFile()
	if err != nil {
		t.Error(err)
	}
	if err := privateKey.Validate(); err != nil {
		t.Error(err)
	}
	_, err = loadPublicKeyFromFile()
	if err != nil {
		t.Error(err)
	}
	if !util.FileExists(privateRsaKeyFile) {
		t.Error("private key file was not created")
	}
	if !util.FileExists(publicRsaKeyFile) {
		t.Error("public key file was not created")
	}
	// clean up on way out
	if err := deleteKeyFiles(privateRsaKeyFile, publicRsaKeyFile); err != nil {
		t.Error(err)
	}
}
