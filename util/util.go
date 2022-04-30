package util

import "crypto/rand"

func GenerateHmac() []byte {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
