package models

import (
	"errors"

	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
)

type Admin struct {
	Auth
	Email string
}

func (a *Admin) GetJwt() (string, int) {
	return "", 0
}

func (a *Admin) ByEmail(email string) error {
	if err := database.Db.Where("email = ?", email).First(&a).Error; err != nil {
		return errors.New("not found")
	}

	return nil
}
