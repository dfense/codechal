package pki

import (
	"math/rand"
	"testing"
)

var (
	privateTestKey = `-----BEGIN RSA PRIVATE KEY-----
	MIIEpAIBAAKCAQEAxvD3yJ3eTT3PhESyGfULuSyDxLk6gFJ7HKpwRsGvHeUkwHyH
	UqfspmXX3pohIz2P1yy1iail0CPKgLBr/hNWgpcGs+2RC1bHe7tL5yeaiHI7mulS
	8feHMFDyHlSUs5Hg6apOJFdZBLbKygsWQqDsO2G/xbwWW9KpRDrkXKvb/1NfV8Ur
	KWIquy9CwMKjvO0ju9ygwOTiSspR2FCynO0umHUwXQzMWF8Rueh65xVv7ojdiYSC
	br8u8B4NszAlqKgnFx9kbedIfb+f0u4el5ZoEXvRg0OLYsaOoBQSxjlWRHyIRnNE
	TAj4jEmMP6/A+9Ja1xNgJkzI113OHF5SimDvfQIDAQABAoIBAFe1makLYR0w6TLp
	jpQ/I2IKrDWpbI9yzfB/fGzVq71Eb4Wl4YuhmYZrVFdCIOYGmEpH3enJPwGbJgbC
	wXoNUJDWwQ/G57HWGrEEjJxnK4yIwJq1z+n6NdIpffW9WKoq4LxkZ3tCP28CoDmf
	1bqedEhh+kjVeg4VvKbmSBRLeP0CH2KswXBjT/HAqiBtQMQa4mmwVxrIzFT/6f1g
	1TpZt7wZzb90EoSeCegb3N/a4vSw0+UBkFe6PQcRpBktHHQ6Xy7YzVl2Lks87Zhk
	Ecu9RrD+G9eOa4DX/EtU55jNxO4xBKq21q85gxFeLXQoJCygIWjGOuzzpQ4obWhb
	wCo5wQkCgYEA0H5cFWx2f0rbWvHwlE5pxJE2RevF1NRuD6CcFyUuhAdht+y+n1iX
	otleTWisyPaf3yRkbIpl5jTv4dBUU9tGj74pEBTgh+n5csJ7a9gigv8AFTCwMfTR
	yaQ9vSH297roHSX7cnBxi8bXFJpUzJP5/LaBshZZHymX0eh53iOd0TMCgYEA9EVp
	i2x3I/FS0138Rr3HDq1zpqn01XOO9uDw/dIXJCUTvNOXgEtilZN+2JCJ1aD11eOC
	PfaKwGHiNqKK0zC2PpzrF+KOFOTVAA/HFDWQeSfGjz75mgr+qjJ+Hc8F6URmzLsL
	IYatAVPVY/lMWb08IXI1QWAcnRBfKQJs//tKnI8CgYEAk6d5dV6sCPgtoxnGxHFH
	7ILeieQw5cpP69dV0/psF+rWZJhQY68tLJJ+e5nPDD/E9xXh3RCim8cPv793iS+4
	qCIHGLGAViD4nTJoj/awck8/csJZdfeo/wHHC4PbUJRYwBPfIKvLbi8ysQ+fUIbX
	uwZRkZrMIQqmz2yxqgVVRgsCgYEAy0aAQKBwvR50OKU77Xq8jkBVv9orfv39eQFU
	S0VsMI4SUM8cgo05axQlOP9/VKHwMqBzoDDs4pASejjloj4lSxG2qlfEuSp8/uIi
	X3T713b8S/SyLjj8GJKQVSoU1zwu+CynZKz4h+RF7j5mBT/vLD4oh1D+Ps6DAlOc
	daGfQ40CgYATwJrxbMo54dkm3PCT0D1yul9zEJN3WFWICujg5eHkReVcpF1Nf5Iy
	z5iCmLs7Da/vb2yAqPlKH2nvadf5ryYncErFpWG4dwDSTR5Dk4MMs/uJ6fTeUDiU
	kVTvbSr8psPtfTqYzc84A2s3eYpV7vwumcewlo4WZrSyVUqjdSFsfw==
	-----END RSA PRIVATE KEY-----`

	publicTestKey = `-----BEGIN RSA PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxvD3yJ3eTT3PhESyGfUL
	uSyDxLk6gFJ7HKpwRsGvHeUkwHyHUqfspmXX3pohIz2P1yy1iail0CPKgLBr/hNW
	gpcGs+2RC1bHe7tL5yeaiHI7mulS8feHMFDyHlSUs5Hg6apOJFdZBLbKygsWQqDs
	O2G/xbwWW9KpRDrkXKvb/1NfV8UrKWIquy9CwMKjvO0ju9ygwOTiSspR2FCynO0u
	mHUwXQzMWF8Rueh65xVv7ojdiYSCbr8u8B4NszAlqKgnFx9kbedIfb+f0u4el5Zo
	EXvRg0OLYsaOoBQSxjlWRHyIRnNETAj4jEmMP6/A+9Ja1xNgJkzI113OHF5SimDv
	fQIDAQAB
	-----END RSA PUBLIC KEY-----`
)

func TestSign(t *testing.T) {
	// message := "Cool mesage to sign"
	message250 := "PsZpHzyLlfzexWbbdaOR BWbBW mSgUjiLCys Fs HtFUFFQQCeSQOSMinXc yIwhrzeSVUmkBrSCsmw cpVJwcxnzCyNyqxweok dflBUbIoEWdsSLFADdW ryjSEPrdbPVxHMZMXKW  nYGdJrLfVXKEocEXsz BFZeYjWSJvAqVIAscgR DgHsIqCvttQKDX uaZw tiBMOEhHvMxgSivCxTc NXUYwIBYbfWOGOFFhoP PPoBEcgIB"
	b64signature, err := Sign(message250)
	if err != nil {
		t.Error(err)
	}
	err = Verify(message250, b64signature)
	if err != nil {
		t.Error(err)
	}

	messageEmpty := ""
	b64signature, err = Sign(messageEmpty)
	if err != nil {
		t.Error(err)
	}
	err = Verify(messageEmpty, b64signature)
	if err != nil {
		t.Error(err)
	}

	messageWeird := "1@#$%^&*()_+=="
	messageWeirdSubtractFront := "@#$%^&*()_+=="
	messageWeirdSubtractBack := "1@#$%^&*()_+="
	b64signature, err = Sign(messageWeird)
	if err != nil {
		t.Error(err)
	}

	err = Verify(messageWeirdSubtractFront, b64signature)
	if err == nil {
		t.Error(err) //should throw an error
	}

	err = Verify(messageWeirdSubtractBack, b64signature)
	if err == nil {
		t.Error(err) //should throw an error
	}
}

// util to make keys i can put into const
// func makePrivatePublicKeys() {
// 	private, public := genRsaKeys(2048)
// 	privatePEM := createPrivateRsaPEM(private)

// 	publicPEM, err := createPublicRsaPEM(public)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// }

// used to create a random base64 string
func generateRandomString(length int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, length)
	for i := range b {
		if i%20 == 0 && i != 0 {
			b[i] = ' '
			continue
		}
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func TestSameHash(t *testing.T) {
	var signature = "MyeNQvh7b9zqkX/bofuEo6enjrnX/Cu57QEf5eSbkJ7PSsHIanh5bLfRm71HLHz+/WiVeGjcNO0ulTzzRbpdhZ8j7JlJRp5CqEanQzmYDMkDmR3eG1bpfCrlKBuVW58i3Zb9CG1Oy1wpTDVyEBbnWL/UD9WjhPS7E7ExkfOXYH12lrIYspBRCvE4sRVyYIBJAJ4t0mvLRceWm/TSySL+PSc1fj9I3YOM5/qMmDXiHC6+ve1bjsR7KGVAGqZ+bO1a2PB6CJs8oXJMeiNzazNiG+02zWe/z5fYjPz0g3sTf0jdWM5vEvnaGCVhiYFJeqXhuZH6QDBxLwvH63vYdhlIRQ=="
	messageEmail := "john@hupla.com"
	b64signature, err := Sign(messageEmail)
	if err != nil {
		t.Error(err)
	}
	if signature != b64signature {
		t.Error("signature doesn't match")
	}
}
