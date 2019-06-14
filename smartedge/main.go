// This shows an example of how to generate a SSH RSA Private/Public key pair and save it locally

package main

import (
	"encoding/json"
	"errors"
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

var (
	errNoCLIMessage = errors.New("must supply message to sign")
)

// entry point into the program.
// wanted to make sure only console output is json based on success or failure
// future versions would have a logger w/level for events or errors to log during runtime
// wrapping errors so can generate json out to console
func main() {

	processCommandLine()

	// TODO add error handling return on any resulting failures
	b64signature, err := pki.Sign(message)
	if err != nil {
		sendResult(errNoCLIMessage)
		log.Fatal(err)
	}

	err = pki.Verify(message, b64signature)
	if err != nil {
		sendResult(err)
		os.Exit(verificationFailed)
	}

	result, err := pki.PrepareResult(message, b64signature)
	if err != nil {
		sendResult(err)
		os.Exit(prepareResultFailed)
	}
	sendResult(result)
}

// sendResult - json serializes any struct whether success or error
func sendResult(result interface{}) {

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "    ")

	switch v := result.(type) {
	case error:
		// wrap all errors with error object for json output
		e := v.(error).Error()
		enc.Encode(model.ErrorResponse{e})
	default:
		enc.Encode(result)
	}

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
			sendResult(err)
			os.Exit(commandLineFailed)
		}
	}

	// make sure we have a message to sign
	if len(flag.Args()) != 1 {
		sendResult(errNoCLIMessage)
		os.Exit(commandLineFailed)
	}
	message = flag.Args()[0]
}
