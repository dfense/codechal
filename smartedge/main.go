// This shows an example of how to generate a SSH RSA Private/Public key pair and save it locally

package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/dfense/codechal/model"
	"github.com/dfense/codechal/pki"
)

var (
	// resetKeys - will delete rsa keys and force regen
	resetKeys *bool
	// rsaKeySize - 1024, 2048, or 4096 optional keysize
	rsaKeySize *int
	// message - string to be hashed and signed
	message string
)

const (
	commandLineFailed = iota + 1
	signingFailed
	verificationFailed
	prepareResultFailed
)

// entry point into the program.
func main() {

	processCommandLine()

	// TODO add error handling return on any resulting failures
	b64signature, err := pki.Sign(message)
	if err != nil {
		sendResult(model.ErrorResponse{err.Error()})
		log.Fatal(err)
	}

	err = pki.Verify(message, b64signature)
	if err != nil {
		sendResult(model.ErrorResponse{err.Error()})
		os.Exit(verificationFailed)
	}

	result, err := pki.PrepareResult(message, b64signature)
	if err != nil {
		sendResult(model.ErrorResponse{err.Error()})
		os.Exit(prepareResultFailed)
	}
	sendResult(result)
}

// sendResult - json serializes any struct whether success or error
func sendResult(result interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "    ")
	enc.Encode(result)
}

// processCommandLine - establishes params available via CLI.
// Requires at least Args() == 1
// rest of params are optional
func processCommandLine() {
	// parse any optional parameters that may have been used on CLI
	resetKeys = flag.Bool("gen_new_keys", false, "generate new rsa keys")
	rsaKeySize = flag.Int("rsa_keysize", 2048, "set rsa key size. ignore if keys already created")
	flag.Parse()
	if *resetKeys {
		pki.ResetKeys()
	}
	if *rsaKeySize != 0 {
		if err := pki.SetRsaKeySize(*rsaKeySize); err != nil {
			sendResult(model.ErrorResponse{err.Error()})
			os.Exit(commandLineFailed)
		}
	}

	// make sure we have a message to sign
	if len(flag.Args()) != 1 {
		sendResult(model.ErrorResponse{"must supply message to sign"})
		os.Exit(commandLineFailed)
	}
	message = flag.Args()[0]
}
