package util

import (
	"crypto/rand"

	"github.com/google/uuid"
)

func GenerateHmac() []byte {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}

type PrincipalInfo struct {
	Uid  uuid.UUID
	Role string
}

type FailMsg struct {
	Reason string `json:"reason"`
}
