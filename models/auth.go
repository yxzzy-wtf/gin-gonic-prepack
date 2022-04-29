package models

import (
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	Base
	PasswordHash      string
	TwoFactorSecret   string
	TwoFactorRecovery string
	Verified          bool
}

func (a *Auth) SetPassword(pass string) error {
	passHash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	a.PasswordHash = string(passHash)
	return nil
}

func (a *Auth) CheckPassword(pass string) error {
	return bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(pass))
}

func (a *Auth) ValidateTwoFactor(tfCode string, stamp time.Time) error {
	if tfCode == "" && a.TwoFactorSecret != "" {
		return errors.New("requires 2FA")
	} else if tfCode == "" && a.TwoFactorSecret == "" {
		return nil
	}

	//TODO two factor
	if len(tfCode) == 6 {
		// Test 2FA
		return errors.New("2FA invalid")
	} else {
		// May be a renewal code
		return errors.New("unlock invalid")
	}
}
