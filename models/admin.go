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
	Email string `gorm:"unique" sql:"index"`
}

const adminJwtDuration = time.Hour * 2

var AdminHmac = util.GenerateHmac(64)

func (a *Admin) GetJwt() (string, int) {
	j := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  a.Uid.String(),
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(adminJwtDuration).Unix(),
		"role": "admin",
	})

	jstr, err := j.SignedString(AdminHmac)
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
