package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/yxzzy-wtf/gin-gonic-prepack/util"
)

func TestAdminGetJwt(t *testing.T) {
	a := Admin{}
	a.Uid = uuid.New()

	jwtToken, maxAge := a.GetJwt()
	if maxAge != int(time.Hour.Seconds()*2) {
		t.Errorf("issued token with incorrect max age, expected %vs but was %vs", time.Hour.Seconds()*2, maxAge)
	}

	testClaims, err := util.ParseJwt(jwtToken, AdminHmac)
	if err != nil {
		t.Errorf("tried to parse valid token but got error %v", err)
	}

	if testClaims["sub"] != a.Uid.String() {
		t.Errorf("`sub` value of %v does not match expected of %v", testClaims["sub"], a.Uid)
	}

	if testClaims["role"] != "admin" {
		t.Errorf("`role` value of %v does not match expected of `admin`", testClaims["role"])
	}

	if _, exists := testClaims["iat"]; !exists {
		t.Errorf("`iat` does not exist in jwt")
	}

	if _, exists := testClaims["exp"]; !exists {
		t.Errorf("`exp` does not exist in jwt")
	}

}
