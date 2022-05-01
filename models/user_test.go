package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/yxzzy-wtf/gin-gonic-prepack/util"
)

func TestUserGetJwt(t *testing.T) {
	u := User{}
	u.Uid = uuid.New()

	jwtToken, maxAge := u.GetJwt()
	if maxAge != int(time.Hour.Seconds()*24) {
		t.Errorf("issued token with incorrect max age, expected %vs but was %vs", time.Hour.Seconds()*24, maxAge)
	}

	testClaims, err := util.ParseJwt(jwtToken, UserHmac)
	if err != nil {
		t.Errorf("tried to parse valid token but got error %v", err)
	}

	if testClaims["sub"] != u.Uid.String() {
		t.Errorf("`sub` value of %v does not match expected of %v", testClaims["sub"], u.Uid)
	}

	if testClaims["role"] != "user" {
		t.Errorf("`role` value of %v does not match expected of `user`", testClaims["role"])
	}

	if _, exists := testClaims["iat"]; !exists {
		t.Errorf("`iat` does not exist in jwt")
	}

	if _, exists := testClaims["exp"]; !exists {
		t.Errorf("`exp` does not exist in jwt")
	}
}
func TestUserGetVerifyJwt(t *testing.T) {
	u := User{}
	u.Uid = uuid.New()

	jwtToken := u.GetVerificationJwt()

	testClaims, err := util.ParseJwt(jwtToken, UserHmac)
	if err != nil {
		t.Errorf("tried to parse valid token but got error %v", err)
	}

	if testClaims["sub"] != u.Uid.String() {
		t.Errorf("`sub` value of %v does not match expected of %v", testClaims["sub"], u.Uid)
	}

	if testClaims["role"] != "verify" {
		t.Errorf("`role` value of %v does not match expected of `verify`", testClaims["role"])
	}

	if _, exists := testClaims["iat"]; !exists {
		t.Errorf("`iat` does not exist in jwt")
	}

	if _, exists := testClaims["exp"]; !exists {
		t.Errorf("`exp` does not exist in jwt")
	}
}

func TestUserGetResetJwt(t *testing.T) {
	u := User{}
	u.Uid = uuid.New()

	jwtToken := u.GetResetPasswordJwt()

	testClaims, err := util.ParseJwt(jwtToken, UserHmac)
	if err != nil {
		t.Errorf("tried to parse valid token but got error %v", err)
	}

	if testClaims["sub"] != u.Uid.String() {
		t.Errorf("`sub` value of %v does not match expected of %v", testClaims["sub"], u.Uid)
	}

	if testClaims["role"] != "reset" {
		t.Errorf("`role` value of %v does not match expected of `reset`", testClaims["role"])
	}

	if _, exists := testClaims["iat"]; !exists {
		t.Errorf("`iat` does not exist in jwt")
	}

	if _, exists := testClaims["exp"]; !exists {
		t.Errorf("`exp` does not exist in jwt")
	}
}
