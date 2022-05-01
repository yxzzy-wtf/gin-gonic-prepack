package util

import (
	"crypto/rand"
	"fmt"

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

type NextMsg struct {
	Next string `json:"nextaction"`
}

func SendEmail(title string, body string, recipient string) {
	//TODO
	fmt.Println("Send", title, body, "to", recipient)
}
