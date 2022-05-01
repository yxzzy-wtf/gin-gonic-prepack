package core

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
	"github.com/yxzzy-wtf/gin-gonic-prepack/models"
	"github.com/yxzzy-wtf/gin-gonic-prepack/util"
)

type login struct {
	UserKey   string `json:"userkey" binding:"required"`
	Password  string `json:"password" binding:"required"`
	TwoFactor string `json:"twofactorcode"`
}

type signup struct {
	UserKey  string `json:"userkey" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type failmsg struct {
	Reason string `json:"reason"`
}

const JwtHeader = "jwt"
const ServicePath = "TODOPATH"
const ServiceDomain = "TODODOMAIN"

func UserSignup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var signupVals signup
		if err := c.ShouldBind(&signupVals); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, failmsg{"Requires username and password"})
			return
		}

		u := models.User{
			Email: signupVals.UserKey,
		}

		if err := u.SetPassword(signupVals.Password); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, failmsg{"Bad password"})
			return
		}

		if err := database.Db.Model(&u).Create(&u).Error; err != nil {
			if err.Error() == "UNIQUE constraint failed: users.email" {
				c.AbortWithStatusJSON(http.StatusInternalServerError, failmsg{"already exists"})
			} else {
				fmt.Println(fmt.Errorf("error: %w", err))
				c.AbortWithStatus(http.StatusInternalServerError)
			}
			return
		}

		c.JSON(http.StatusOK, map[string]string{"id": u.Uid.String()})
	}
}

func UserLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginVals login
		if err := c.ShouldBind(&loginVals); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, failmsg{"Requires username and password"})
		}

		u := models.User{}
		if err := u.ByEmail(loginVals.UserKey); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if err, returnErr := u.Login(loginVals.Password, loginVals.TwoFactor); err != nil {
			if returnErr {
				c.AbortWithStatusJSON(http.StatusUnauthorized, failmsg{err.Error()})
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			return
		}

		jwt, maxAge := u.GetJwt()
		c.SetCookie(JwtHeader, jwt, maxAge, ServicePath, ServiceDomain, true, true)
	}
}

func AdminLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginVals login
		if err := c.ShouldBind(&loginVals); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, failmsg{"requires username and password"})
		}

		if loginVals.TwoFactor == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, failmsg{"admin access requires 2FA"})
			return
		}

		a := models.Admin{}
		if err := a.ByEmail(loginVals.UserKey); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if err, returnErr := a.Login(loginVals.Password, loginVals.TwoFactor); err != nil {
			if returnErr {
				c.AbortWithStatusJSON(http.StatusUnauthorized, failmsg{err.Error()})
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			return
		}

		jwt, maxAge := a.GetJwt()
		c.SetCookie(JwtHeader, jwt, maxAge, ServicePath, ServiceDomain, true, true)
	}
}

func genericAuth(expectedRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.GetHeader(JwtHeader)
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, failmsg{"requires `" + JwtHeader + "` header"})
			return
		}

		claims, err := parseJwt(tokenStr, models.UserHmac)
		if err != nil {
			if strings.HasPrefix(err.Error(), "token ") || err.Error() == "signature is invalid" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, failmsg{err.Error()})
			} else {
				fmt.Println(err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, failmsg{"something went wrong"})
			}
			return
		}
		if claims["role"] != expectedRole {
			c.AbortWithStatusJSON(http.StatusUnauthorized, failmsg{"wrong access role"})
			return
		}

		uid, err := uuid.Parse(claims["sub"].(string))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, failmsg{"cannot extract sub"})
			return
		}

		c.Set("principal", util.PrincipalInfo{Uid: uid, Role: expectedRole})
	}
}

func UserAuth() gin.HandlerFunc {
	return genericAuth("user")
}

func AdminAuth() gin.HandlerFunc {
	return genericAuth("admin")
}

func parseJwt(tokenStr string, hmac []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("bad signing method %v", token.Header["alg"])
		}

		return hmac, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return jwt.MapClaims{}, err
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
