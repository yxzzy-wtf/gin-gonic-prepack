package models

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
	"github.com/yxzzy-wtf/gin-gonic-prepack/util"
)

type User struct {
	Auth
	Email string `gorm:"unique;index"`
}

const userJwtDuration = time.Hour * 24

var UserHmac = util.GenerateHmac()

func (u *User) GetJwt() (string, int) {
	j := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  u.Uid.String(),
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(userJwtDuration).Unix(),
		"role": "user",
	})

	jstr, err := j.SignedString(UserHmac)
	if err != nil {
		// we should ALWAYS be able to build and sign a str
		panic(err)
	}

	return jstr, int(userJwtDuration.Seconds())
}

func (u *User) GetVerificationJwt() string {
	j := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  u.Uid.String(),
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
		"role": "verify",
	})

	jstr, err := j.SignedString(UserHmac)
	if err != nil {
		// we should ALWAYS be able to build and sign a str
		panic(err)
	}

	return jstr
}

func (u *User) GetResetPasswordJwt() string {
	j := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  u.Uid.String(),
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Minute * 15).Unix(),
		"role": "reset",
	})

	jstr, err := j.SignedString(UserHmac)
	if err != nil {
		// we should ALWAYS be able to build and sign a str
		panic(err)
	}

	return jstr
}

func (u *User) ByEmail(email string) error {
	if err := database.Db.Where("email = ?", email).First(&u).Error; err != nil {
		return errors.New("not found")
	}

	return nil
}

func (u *User) Create() error {
	if u.Uid != uuid.Nil {
		return errors.New("cannot create with existing uid")
	}

	if err := database.Db.Create(&u).Error; err != nil {
		return err
	}

	return nil
}

func (u *User) Save() error {
	if u.Uid == uuid.Nil {
		return errors.New("cannot save without uid")
	}

	if err := database.Db.Save(&u).Error; err != nil {
		return err
	}

	return nil
}
