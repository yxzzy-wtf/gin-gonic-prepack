package util

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

func GenerateHmac(length int) []byte {
	b := make([]byte, length)
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

func SendEmail(title string, body string, recipients []string) {
	//TODO
	log.Println("Send", title, body, "to", recipients)
}

func ParseJwt(tokenStr string, hmac []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("bad signing method %v", token.Header["alg"])
		}

		return hmac, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return jwt.MapClaims{}, err
	}
}
