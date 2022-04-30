package models

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
	"github.com/yxzzy-wtf/gin-gonic-prepack/util"
)

type Admin struct {
	Auth
	Email string
}

const adminJwtDuration = time.Hour * 2

var adminHmac = util.GenerateHmac()

func (a *Admin) GetJwt() (string, int) {
	exp := time.Now().Add(adminJwtDuration)
	j := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  a.Uid.String(),
		"iat":  time.Now(),
		"exp":  exp,
		"role": "admin",
	})

	jstr, err := j.SignedString(adminHmac)
	if err != nil {
		// we should ALWAYS be able to build and sign a str
		panic(err)
	}

	return jstr, int(adminJwtDuration.Seconds())
}

func (a *Admin) ByEmail(email string) error {
	if err := database.Db.Where("email = ?", email).First(&a).Error; err != nil {
		return errors.New("not found")
	}

	return nil
}
