package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
	"github.com/yxzzy-wtf/gin-gonic-prepack/models"

	"github.com/gin-gonic/gin"
	_ "github.com/golang-jwt/jwt"
	"gorm.io/gorm"
)

func Migrate(g *gorm.DB) {
	g.AutoMigrate(&models.User{})
	g.AutoMigrate(&models.Admin{})
}

func main() {
	db := database.Init()
	Migrate(db)

	r := gin.Default()
	v1 := r.Group("/v1")

	// Ping functionality
	v1.GET("/doot", doot())

	// Standard user login
	v1.POST("/signup", userSignup())
	v1.POST("/login", userLogin())
	v1Sec := v1.Group("/sec", userAuth())

	v1Sec.GET("/doot", doot())

	// Administrative login
	v1.POST("/admin", adminLogin())
	v1Admin := v1.Group("/adm", adminAuth())

	v1Admin.GET("/doot", doot())

	// Start server
	if err := http.ListenAndServe(":9091", r); err != nil {
		log.Fatal(err)
	}
}

func doot() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]string{"snoot": "dooted"})
	}
}

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

func userLogin() gin.HandlerFunc {
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

func userSignup() gin.HandlerFunc {
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

func adminLogin() gin.HandlerFunc {
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

func userAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwt := c.GetHeader(JwtHeader)
		if jwt == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, failmsg{"requires `" + JwtHeader + "` header"})
			return
		}

		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

func adminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwt := c.GetHeader(JwtHeader)
		if jwt == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, failmsg{"requires `" + JwtHeader + "` header"})
			return
		}

		c.AbortWithStatus(http.StatusUnauthorized)
	}
}
