package models

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
	"github.com/yxzzy-wtf/gin-gonic-prepack/util"
)

type User struct {
	Auth
	Email string `gorm:"unique"`
}

const userJwtDuration = time.Hour * 24

var userHmac = util.GenerateHmac()

func (u *User) GetJwt() (string, int) {
	exp := time.Now().Add(userJwtDuration)
	j := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  u.Uid.String(),
		"iat":  time.Now(),
		"exp":  exp,
		"role": "user",
		"tid":  u.Tenant.String(),
	})

	jstr, err := j.SignedString(userHmac)
	if err != nil {
		// we should ALWAYS be able to build and sign a str
		panic(err)
	}

	return jstr, int(userJwtDuration.Seconds())
}

func (u *User) ByEmail(email string) error {
	if err := database.Db.Where("email = ?", email).First(&u).Error; err != nil {
		return errors.New("not found")
	}

	return nil
}
