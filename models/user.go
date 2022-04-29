package models

import (
	"errors"

	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
)

type User struct {
	Auth
	Email string `gorm:"unique"`
}

func (u *User) GetJwt() (string, int) {
	return "", 0
}

func (u *User) ByEmail(email string) error {
	if err := database.Db.Where("email = ?", email).First(&u).Error; err != nil {
		return errors.New("not found")
	}

	return nil
}
