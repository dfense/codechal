// This shows an example of how to generate a SSH RSA Private/Public key pair and save it locally

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dfense/codechal/pki"
)

func main() {

	resetKeys := flag.Bool("gen_new_keys", false, "generate new rsa keys")
	rsaKeySize := flag.Int("rsa_keysize", 2048, "set rsa key size. ignore if keys already created")
	flag.Parse()

	if *resetKeys {
		pki.ResetKeys()
	}
	if *rsaKeySize != 0 {
		if err := pki.SetRsaKeySize(*rsaKeySize); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if len(flag.Args()) != 1 {
		log.Fatal("must supply message to sign")
	}

	message := flag.Args()[0]
	fmt.Printf("rsaKeySize: %d\n", *rsaKeySize)
	b64signature, err := pki.Sign(message)
	if err != nil {
		log.Fatal(err)
	}

	err = pki.Verify(message, b64signature)
	if err != nil {
		fmt.Printf("Verification Failed !!")
	}
	fmt.Println("== Message Verified ==")

	result, err := pki.PrepareResult(message, b64signature)
	if err != nil {
		log.Fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "    ")
	enc.Encode(result)

}
