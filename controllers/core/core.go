// The controllers.core package should act as the prime pin controlling
// User or Admin activity throughout the rest of the site. It should offer
// Login lifecycle methods, as well as per-request JWT-based authentication.
package core

import (
	"fmt"
	"net/http"

	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/yxzzy-wtf/gin-gonic-prepack/config"
	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
	"github.com/yxzzy-wtf/gin-gonic-prepack/models"
	"github.com/yxzzy-wtf/gin-gonic-prepack/util"
)

// Basic structure for login calls to both Admin and User access
type login struct {
	UserKey   string `json:"userkey" binding:"required,email"`
	Password  string `json:"password" binding:"required"`
	TwoFactor string `json:"twofactorcode"`
}

// Basic structure for users to sign up based on models.User
type signup struct {
	UserKey  string `json:"userkey" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Body query responsible for requesting a password reset
type forgotten struct {
	UserKey string `json:"userkey" binding:"required,email"`
}

// Body query responsible for resetting a password with a reset token
type reset struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"password" binding:"required"`
}

// The default name of the JWT header expected. It is localized and can be changed
// to anything valid here
const JwtHeader = "jwt"

// User signup process. Tests that an email and password has been supplied, that
// the email is unique and that the password is valid, then creates the user and
// sends a verification email to the given email address. To prevent enumeration
// attacks, this method will always return {next:"verification pending"}, even
// if the given email is already in the system. If the email is already in the system,
// that account will be emailed notifying them of the signup attempt.
// @Summary User signup
// @Description Sign a user up for a new account
// @Accept json
// @Produce json
// @Param userkey body string true "user email"
// @Param password body string true "user password"
// @Router /signup [post]
// @Success 200
// @Failure 400 "userkey missing, or password missing or not strong enough"
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
				go util.SendEmail("Signup Attempt", "Someone tried to sign up with this email. This is a cursory warning. If it was you, good news! You're already signed up!", []string{u.Email})
			}
		} else {
			// Send verification
			verifyToken := u.GetVerificationJwt()
			go util.SendEmail("Verify Email", "Helloooo! Go here to verify: http://localhost:9091/v1/verify?verify="+verifyToken, []string{u.Email})
		}

		c.JSON(http.StatusOK, util.NextMsg{Next: "verification pending"})
	}
}

// Function to log in a user based on a given email, password [and 2FA code]. Similar to
// AdminLogin but with slight differences. Resistant to enumeration attacks as error messages
// are only displayed IFF the user exists AND the password is correct, otherwise a 401 is returned
// @Summary User login
// @Description Secured login for any user accounts
// @Accept json
// @Produce json
// @Param userkey body string true "user email"
// @Param password body string true "user password"
// @Param twofactorcode body string false "the 2fa token for the user, if activated"
// @Router /login [post]
// @Success 200
// @Failure 401 "not found or credentials invalid"
// @Failure 400 "userkey or password missing"
// @Header 200 {string} jwt "The authentication token for this session, valid for 24h"
func UserLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Why do we do this? Assuming a consistent and stable service and an attacker
		// with an equally consistent internet connection, it is possible to
		// still launch an enumeration attack by comparing the time of a known
		// extant address and a known non-extant one. For this reason, login duration is
		// floored to at least 5 seconds
		minTime := make(chan bool)
		go func(c chan bool) {
			time.Sleep(time.Second * 5)
			minTime <- true
		}(minTime)

		var loginVals login
		if err := c.ShouldBind(&loginVals); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, util.FailMsg{Reason: "Requires username and password"})
			<-minTime
			return
		}

		u := models.User{}
		if err := u.ByEmail(loginVals.UserKey); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			<-minTime
			return
		}

		if err, returnErr := u.Login(loginVals.Password, loginVals.TwoFactor); err != nil {
			if returnErr {
				c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: err.Error()})
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			<-minTime
			return
		}

		if loginVals.TwoFactor != "" && !checkTwoFactorNotReused(&u.Auth, loginVals.TwoFactor) {
			fmt.Printf("WARNING: two factor code %v reused for %v\n", loginVals.TwoFactor, u.Uid)
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: "2fa reused"})
			<-minTime
			return
		}

		jwt, maxAge := u.GetJwt()
		c.SetCookie(JwtHeader, jwt, maxAge, "/v1/sec/", "", true, true)
		<-minTime
	}
}

// Parses a given JWT token and attempts to verify the `sub` in that token IFF
// the token role == "verify". Verifying an already-verified user returns
// a 200OK{next:"login"} without any action
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

		c.JSON(http.StatusOK, util.NextMsg{Next: "login"})
	}
}

// Indicates to the service that the user has forgotten their password and
// requires a reset token; then sends an email with the appropriate reset token
// to the user email in question. The same response will be returned if the given
// user email does not exist
// @Summary Forgot password
// @Description Request a password reset for the provided userkey
// @Accept json
// @Produce json
// @Param userkey body string true "user email to reset"
// @Router /forgot [post]
// @Success 200
// @Failure 400 "userkey not provided"
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
			go util.SendEmail("Forgot Password", "Token to reset password: "+forgotJwt, []string{u.Email})
		}

		c.JSON(http.StatusOK, util.NextMsg{Next: "check email to reset"})
	}
}

// Method to reset a password, requiring a new password and a valid JWT token
// of role="reset".
// @Summary Password reset
// @Description Use a JWT token to validate and reset a password
// @Accept json
// @Produce json
// @Param token body string true "the token emailed to the user"
// @Param password body string true "the new password value"
// @Router /reset [post]
// @Success 200
// @Failure 400 "token and password not provided"
// @Failure 401 "bad token or user not found"
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

// Admin login functionality, similar to user login but requires 2FA to be set up.
// @Summary User login
// @Description Secured login for any user accounts
// @Accept json
// @Produce json
// @Param userkey body string true "user email"
// @Param password body string true "user password"
// @Param twofactorcode body string true "the 2fa token"
// @Router /admin [post]
// @Success 200
// @Failure 401 "not found or credentials invalid"
// @Failure 400 "userkey, 2fa token or password missing"
// @Header 200 {string} jwt "The authentication token for this session, valid for 24h"
func AdminLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Same as user slowdown
		minTime := make(chan bool)
		go func(c chan bool) {
			time.Sleep(time.Second * 5)
			minTime <- true
		}(minTime)

		var loginVals login
		if err := c.ShouldBind(&loginVals); err != nil || loginVals.TwoFactor == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, util.FailMsg{Reason: "Requires username, 2FA and password"})
			<-minTime
			return
		}

		a := models.Admin{}
		if err := a.ByEmail(loginVals.UserKey); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			<-minTime
			return
		}

		if err, returnErr := a.Login(loginVals.Password, loginVals.TwoFactor); err != nil {
			if returnErr {
				c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: err.Error()})
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			<-minTime
			return
		}

		if loginVals.TwoFactor != "" && !checkTwoFactorNotReused(&a.Auth, loginVals.TwoFactor) {
			fmt.Printf("WARNING: two factor code %v reused by admin %v\n", loginVals.TwoFactor, a.Uid)
			c.AbortWithStatusJSON(http.StatusUnauthorized, util.FailMsg{Reason: "2fa reused"})
			<-minTime
			return
		}

		jwt, maxAge := a.GetJwt()
		c.SetCookie(JwtHeader, jwt, maxAge, "/v1/sec/", "", true, true)
		<-minTime
	}
}

// Generic authorization applicable to both User and Admin roles. This takes an
// expected role and HMAC, parses the JWT, and sets the PrincipalInfo accordingly.
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

// Wrapper for User authentication, effectively `genericAuth("user", models.UserHmac)`
func UserAuth() gin.HandlerFunc {
	return genericAuth("user", models.UserHmac)
}

// Wrapper for User authentication, effectively `genericAuth("admin", models.AdminHmac)`
func AdminAuth() gin.HandlerFunc {
	return genericAuth("admin", models.AdminHmac)
}

// A handler to attach to any method which requires a two-factor check
// at the time of calling. An example of this might be: changing email,
// changing password, or other high-sensitivity actions that warrant
// an extra 2FA check.
func LiveTwoFactor() gin.HandlerFunc {
	return func(c *gin.Context) {
		pif, exists := c.Get("principal")
		p := pif.(util.PrincipalInfo)
		if !exists {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		var a models.Auth
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

func StarterAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		var count int64
		database.Db.Model(&models.Admin{}).Count(&count)
		if count != 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		var signupVals signup
		if err := c.ShouldBind(&signupVals); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, util.FailMsg{Reason: "invalid fields, requires userkey=email and password"})
			return
		}

		a := models.Admin{}
		if err := a.ByEmail(signupVals.UserKey); err == nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		a.Email = signupVals.UserKey
		a.SetPassword(signupVals.Password)
		a.GenerateNewTwoFactorSecret()

		if err := database.Db.Create(&a).Error; err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		go util.SendEmail("Admin Created", "A new admin, "+a.Email+", has been created", config.Config.AdminEmails)

		c.JSON(http.StatusOK, util.NextMsg{Next: "db verify"})
	}
}

// Ping functionality
// @Summary ping example
// @Description unauthenticated ping
// @Product json
// @Router /doot [get]
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

// @Summary ping example
// @Description user ping and login check
// @Product json
// @Router /sec/doot [get]
// @Param jwt header string true "JWT Cookie set by /login"
func UserDoot() gin.HandlerFunc {
	return Doot()
}

// @Summary ping example
// @Description admin ping and login check
// @Product json
// @Router /adm/doot [get]
// @Param jwt header string true "JWT Cookie set by /admin"
func AdminDoot() gin.HandlerFunc {
	return Doot()
}

// To prevent 2FA theft attacks, a TOTP needs to be... well, an OTP. This will
// check the database to confirm that this user UID has never used this token in
// past, and will fail if such a token has been used by this user. It will then
// add this UID:code combination to the TotpUsage table to prevent future re-use.
// There may be some sense in adding a means by which to clear out TotpUsage objects
// older than a certain time.
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
