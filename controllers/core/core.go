package core

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
	"github.com/yxzzy-wtf/gin-gonic-prepack/models"
	"github.com/yxzzy-wtf/gin-gonic-prepack/util"
)

type login struct {
	UserKey   string `json:"userkey" binding:"required,email"`
	Password  string `json:"password" binding:"required"`
	TwoFactor string `json:"twofactorcode"`
}

type signup struct {
	UserKey  string `json:"userkey" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type forgotten struct {
	UserKey string `json:"userkey" binding:"required,email"`
}

type reset struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"password" binding:"required"`
}

const JwtHeader = "jwt"

func UserSignup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var signupVals signup
		if err := c.ShouldBind(&signupVals); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, util.FailMsg{Reason: "invalid fields, requires userkey=email and password"})
			return
		}

		u := models.User{
			Email: signupVals.UserKey,
		}

		if err := u.SetPassword(signupVals.Password); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, util.FailMsg{Reason: "bad password"})
			return
		}

		if err := u.Create(); err != nil {
			if err.Error() != "UNIQUE constraint failed: users.email" {
				fmt.Println(fmt.Errorf("error: %w", err))
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			} else {
				// Email conflict means we should still mock verify
				go util.SendEmail("Signup Attempt", "Someone tried to sign up with this email. This is a cursory warning. If it was you, good news! You're already signed up!", u.Email)
			}
		} else {
			// Send verification
			verifyToken := u.GetVerificationJwt()
			go util.SendEmail("Verify Email", "Helloooo! Go here to verify: http://localhost:9091/v1/verify?verify="+verifyToken, u.Email)
		}

		c.JSON(http.StatusOK, util.NextMsg{Next: "verification pending"})
	}
}

func UserLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginVals login
		if err := c.ShouldBind(&loginVals); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, util.FailMsg{Reason: "Requires username and password"})
			return
		}

		u := models.User{}
		if err := u.ByEmail(loginVals.UserKey); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if err, returnErr := u.Login(loginVals.Password, loginVals.TwoFactor); err != nil {
			if returnErr {
				c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: err.Error()})
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			return
		}

		if loginVals.TwoFactor != "" && !checkTwoFactorNotReused(&u.Auth, loginVals.TwoFactor) {
			fmt.Printf("WARNING: two factor code %v reused for %v\n", loginVals.TwoFactor, u.Uid)
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: "2fa reused"})
			return
		}

		jwt, maxAge := u.GetJwt()
		c.SetCookie(JwtHeader, jwt, maxAge, "/v1/sec/", "", true, true)
	}
}

func checkTwoFactorNotReused(a *models.Auth, tfCode string) bool {
	var count int64
	database.Db.Model(&models.TotpUsage{}).Where("login_uid = ? AND code = ?", a.Uid, tfCode).Count(&count)

	if count > 0 {
		// We found a token, should reject
		return false
	}

	used := models.TotpUsage{
		LoginUid: a.Uid,
		Code:     tfCode,
		Used:     time.Now(),
	}
	go database.Db.Create(&used)

	return true
}

func UserVerify() gin.HandlerFunc {
	return func(c *gin.Context) {
		verifyJwt, _ := c.GetQuery("verify")

		claims, err := util.ParseJwt(verifyJwt, models.UserHmac)
		if err != nil || claims["role"] != "verify" {
			fmt.Println("bad claim or role not 'verify'", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Yay! Jwt is a verify token, let's verify the linked user
		uid, err := uuid.Parse(claims["sub"].(string))
		if err != nil {
			fmt.Println("sub should ALWAYS be valid uuid at this point??", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		verifying := models.User{
			Auth: models.Auth{
				Base: models.Base{
					Uid: uid,
				},
			},
		}

		if err := database.Db.Find(&verifying).Error; err != nil {
			fmt.Println("could not find user", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if verifying.Verified {
			// User already verified
			c.JSON(http.StatusOK, util.NextMsg{Next: "verified"})
			return
		}

		verifying.Verified = true
		if err := verifying.Save(); err != nil {
			fmt.Println("could not verify user", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.JSON(http.StatusOK, util.NextMsg{Next: "verified"})
	}
}

func UserForgotPassword() gin.HandlerFunc {
	return func(c *gin.Context) {
		var forgotVals forgotten
		if err := c.ShouldBind(&forgotVals); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, util.FailMsg{Reason: "requires email"})
			return
		}

		u := models.User{}
		if err := u.ByEmail(forgotVals.UserKey); err == nil {
			// Actually send renew token
			forgotJwt := u.GetResetPasswordJwt()
			go util.SendEmail("Forgot Password", "Token to reset password: "+forgotJwt, u.Email)
		}

		c.JSON(http.StatusOK, util.NextMsg{Next: "check email to reset"})
	}
}

func UserResetForgottenPassword() gin.HandlerFunc {
	return func(c *gin.Context) {
		var resetVals reset
		if err := c.ShouldBind(&resetVals); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, util.FailMsg{Reason: "requires new pass and token"})
			return
		}

		claims, err := util.ParseJwt(resetVals.Token, models.UserHmac)
		if err != nil || claims["role"] != "reset" {
			fmt.Println("bad claim or role not 'reset'", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		uid, err := uuid.Parse(claims["sub"].(string))
		if err != nil {
			fmt.Println("sub should ALWAYS be valid uuid at this point??", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		resetting := models.User{
			Auth: models.Auth{
				Base: models.Base{
					Uid: uid,
				},
			},
		}

		if err := database.Db.Find(&resetting).Error; err != nil {
			fmt.Println("could not find user", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		resetting.SetPassword(resetVals.NewPassword)
		if err := resetting.Save(); err != nil {
			fmt.Println("could not save user", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.JSON(http.StatusOK, util.NextMsg{Next: "login"})
	}
}

func AdminLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginVals login
		if err := c.ShouldBind(&loginVals); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, util.FailMsg{Reason: "requires username and password"})
		}

		if loginVals.TwoFactor == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: "admin access requires 2FA"})
			return
		}

		a := models.Admin{}
		if err := a.ByEmail(loginVals.UserKey); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if err, returnErr := a.Login(loginVals.Password, loginVals.TwoFactor); err != nil {
			if returnErr {
				c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: err.Error()})
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			return
		}

		if loginVals.TwoFactor != "" && !checkTwoFactorNotReused(&a.Auth, loginVals.TwoFactor) {
			fmt.Printf("WARNING: two factor code %v reused for admin %v\n", loginVals.TwoFactor, a.Uid)
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: "2fa reused"})
			return
		}

		jwt, maxAge := a.GetJwt()
		c.SetCookie(JwtHeader, jwt, maxAge, "/v1/adm", "", true, true)
	}
}

func genericAuth(expectedRole string, hmac []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.GetHeader(JwtHeader)
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: "requires `" + JwtHeader + "` header"})
			return
		}

		claims, err := util.ParseJwt(tokenStr, hmac)
		if err != nil {
			if strings.HasPrefix(err.Error(), "token ") || err.Error() == "signature is invalid" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: err.Error()})
			} else {
				fmt.Println(err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, util.FailMsg{Reason: "something went wrong"})
			}
			return
		}
		if claims["role"] != expectedRole {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: "wrong access role"})
			return
		}

		uid, err := uuid.Parse(claims["sub"].(string))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: "cannot extract sub"})
			return
		}

		c.Set("principal", util.PrincipalInfo{Uid: uid, Role: expectedRole})
	}
}

func UserAuth() gin.HandlerFunc {
	return genericAuth("user", models.UserHmac)
}

func AdminAuth() gin.HandlerFunc {
	return genericAuth("admin", models.AdminHmac)
}

// A handler to attach to any method which requires a two-factor check
// at the time of calling. An example of this might be: changing email,
// changing password, or other high-sensitivity actions that warrant
// an extra 2FA check.
func LiveTwoFactor() gin.HandlerFunc {
	return func(c *gin.Context) {
		fmt.Println("Required live 2fa")
		pif, exists := c.Get("principal")
		p := pif.(util.PrincipalInfo)
		if !exists {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		var a models.Auth
		fmt.Println(p)
		if p.Role == "user" {
			u := models.User{}
			if err := database.Db.Find(&u, "uid = ?", p.Uid).Error; err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			a = u.Auth
		} else if p.Role == "admin" {
			adm := models.Admin{}
			if err := database.Db.Find(&adm, "uid = ?", p.Uid).Error; err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			a = adm.Auth
		}

		if a.TwoFactorSecret != "" {
			tfCode, exists := c.GetQuery("twofactorcode")
			if !exists || len(tfCode) != 6 {
				c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: "2fa required"})
				return
			}

			if err := a.ValidateTwoFactor(tfCode, time.Now()); err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: err.Error()})
				return
			}

			if !checkTwoFactorNotReused(&a, tfCode) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: "2fa reused"})
				return
			}
		}

	}
}

func Doot() gin.HandlerFunc {
	return func(c *gin.Context) {
		piCtx, exists := c.Get("principal")
		if exists {
			pi := piCtx.(util.PrincipalInfo)
			dooter := pi.Role + ":" + pi.Uid.String()
			c.JSON(http.StatusOK, map[string]string{"snoot": "dooted by " + dooter})
		} else {
			c.JSON(http.StatusOK, map[string]string{"snoot": "dooted"})
		}
	}
}
