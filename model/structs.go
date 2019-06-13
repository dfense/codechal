package model

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
