package models

import (
	"testing"
	"time"

	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
)

func TestBadPasswords(t *testing.T) {
	a := Auth{}

	if err := a.SetPassword("short"); err.Error() != "password too short" {
		t.Errorf("allowed short password")
	}

	if err := a.SetPassword("tqr9wyfPassword9k8rwcd"); err.Error() != "contains phrase 'password'" {
		t.Errorf("allowed password containing the word 'password'")
	}

	if err := a.SetPassword("qc2q2fn34dqifqu23j7dp0"); err != nil {
		t.Errorf("rejected acceptable password")
	}
}

func TestSettingPassword(t *testing.T) {
	a := Auth{}

	if a.PasswordHash != "" {
		t.Errorf("passwordhash comes with default value")
	}

	a.SetPassword("This-q2o37rcfy2ij34tgjwi374f3w")
	ph := a.PasswordHash
	if ph == "" {
		t.Errorf("passwordhash was not set")
	}

	a.SetPassword("Different-q2o37rcfy2ij34tgjwi374f3w")
	if ph == a.PasswordHash {
		t.Errorf("password hashes are the same across different passwords")
	}

}

func TestPasswordFlow(t *testing.T) {
	a := Auth{}

	a.SetPassword("Base-w894t7yw9xj8fxh834dr32")
	if err := a.CheckPassword("Incorrect-w894t7yw9xj8fxh834dr32"); err == nil {
		t.Errorf("did not fail when provided the wrong password")
	}

	if err := a.CheckPassword("Base-w894t7yw9xj8fxh834dr32"); err != nil {
		t.Errorf("failed when provided the right password")
	}

	a.SetPassword("Secondary-w894t7yw9xj8fxh834dr32")
	if err := a.CheckPassword("Base-w894t7yw9xj8fxh834dr32"); err == nil {
		t.Errorf("did not fail when provided the original password")
	}

	if err := a.CheckPassword("Secondary-w894t7yw9xj8fxh834dr32"); err != nil {
		t.Errorf("failed when provided the correct updated password")
	}
}

func TestTwoFactorWhenNotSet(t *testing.T) {
	a := Auth{}
	if err := a.ValidateTwoFactor("ZZZZZZ", time.Now()); err == nil {
		t.Errorf("no 2fa set up but code provided, should get err")
	}

	if err := a.ValidateTwoFactor("", time.Now()); err != nil {
		t.Errorf("no code give but no 2fa set up, should not have errored")
	}
}

func TestTwoFactor(t *testing.T) {
	database.InitTestDb()

	a := Auth{}
	a.TwoFactorSecret = "AAAAAAAAAAAAAAAA"

	testTime := time.Date(2022, 1, 5, 18, 0, 0, 0, time.UTC)
	expected := "566833"

	if err := a.ValidateTwoFactor("000000", testTime); err == nil {
		t.Errorf("accepted invalid token")
	}

	if err := a.ValidateTwoFactor(expected, testTime); err != nil {
		t.Errorf("rejected expected token at T0 of period")
	}

	if err := a.ValidateTwoFactor(expected, testTime.Add(29*time.Second)); err != nil {
		t.Errorf("rejected expected token at T29 of period")
	}

	if err := a.ValidateTwoFactor(expected, testTime.Add(35*time.Second)); err == nil {
		t.Errorf("accepted valid token at T35 of period (token is from last period)")
	}
}

func TestCombinedLogin(t *testing.T) {
	a := Auth{}
	a.SetPassword("q2ricy2rqi3c4r23rcou")
	a.TwoFactorSecret = "AAAAAAAAAAAAAAAA"
	testTime := time.Date(2022, 1, 5, 18, 0, 0, 0, time.UTC)
	expected := "566833"

	err, show := a.login("q2ricy2rqi3c4r23rcou", expected, testTime)
	if err == nil || err.Error() != "not yet verified" {
		t.Errorf("validated login of unverified user")
	}
	if !show {
		t.Errorf("unverified is an acceptable message to show, did not indicate true")
	}

	err, show = a.login("q2ricy2rqi3c4r23rcou", "000000", testTime)
	if err == nil || err.Error() != "2fa invalid" {
		t.Errorf("validated incorrect 2fa code")
	}
	if !show {
		t.Errorf("bad 2fa is an acceptable message to show, did not indicate true")
	}

	err, show = a.login("bad", "000000", testTime)
	if err == nil {
		t.Errorf("validated bad password")
	}
	if show {
		t.Errorf("bad passwrd not an acceptable message to show, but indicated true")
	}

	a.Verified = true
	err, _ = a.login("q2ricy2rqi3c4r23rcou", expected, testTime)
	if err != nil {
		t.Errorf("failed good login")
	}
}
