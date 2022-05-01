package models

import (
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
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
	if len(pass) < 12 {
		return errors.New("password too short")
	}

	if strings.Contains(strings.ToLower(pass), "password") {
		return errors.New("contains phrase 'password'")
	}

	passHash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	a.PasswordHash = string(passHash)
	return nil
}

func (a *Auth) Login(pass string, tfCode string) (error, bool) {
	return a.login(pass, tfCode, time.Now())
}

func (a *Auth) login(pass string, tfCode string, stamp time.Time) (error, bool) {
	if err := a.CheckPassword(pass); err != nil {
		return err, false
	}

	if err := a.ValidateTwoFactor(tfCode, stamp); err != nil {
		return err, true
	}

	if !a.Verified {
		return errors.New("not yet verified"), true
	}

	return nil, false
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
		expect, err := totp.GenerateCode(a.TwoFactorSecret, stamp)
		if err != nil {
			return errors.New("could not process 2fa")
		}
		if expect == tfCode {
			return nil
		}
		return errors.New("2fa invalid")
	} else {
		// May be a renewal code
		return errors.New("unlock invalid")
	}
}
