package model

// NOTE on model package:
// I am overly sensitive to separation of model or domain objects
// in go (and in general) especially due to golang cyclic import rules
// not to mention better abstract interface designs etc.

// KeyResponse - successful result to stdout
type KeyResponse struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Pubkey    string `json:"pubkey"`
}

// ErrorResponse - unsuccessful result to stdout
type ErrorResponse struct {
	Error string `json:"error"`
}
