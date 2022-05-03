package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/yxzzy-wtf/gin-gonic-prepack/config"
	"github.com/yxzzy-wtf/gin-gonic-prepack/controllers/core"
	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
	"github.com/yxzzy-wtf/gin-gonic-prepack/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func Migrate(g *gorm.DB) {
	g.AutoMigrate(&models.User{})
	g.AutoMigrate(&models.Admin{})
	g.AutoMigrate(&models.TotpUsage{})
}

func main() {
	config.LoadConfig()

	db := database.Init()
	Migrate(db)

	r := gin.Default()
	v1 := r.Group("/v1")

	// Ping functionality
	v1.GET("/doot", core.Doot())

	if config.Config.AllowFreshAdminGeneration {
		var adminCount int64
		database.Db.Model(models.Admin{}).Count(&adminCount)

		if adminCount == 0 {
			randUri := uuid.New()
			v1.POST("/"+randUri.String(), core.StarterAdmin())

			fmt.Println("#################")
			fmt.Println("No admins and AllowFreshAdminGeneration=TRUE")
			fmt.Println("Sign up starter at: /" + randUri.String())
			fmt.Println("#################")
		}
	}

	// Standard user signup, verify, login and forgot/reset pw
	v1.POST("/signup", core.UserSignup())
	v1.POST("/login", core.UserLogin())
	v1.GET("/verify", core.UserVerify())
	v1.POST("/forgot", core.UserForgotPassword())
	v1.POST("/reset", core.UserResetForgottenPassword())
	v1Sec := v1.Group("/sec", core.UserAuth())

	v1Sec.GET("/doot", core.Doot())
	v1Sec.GET("/2fa-doot", core.LiveTwoFactor(), core.Doot())

	// Administrative login
	v1.POST("/admin", core.AdminLogin())
	v1Admin := v1.Group("/adm", core.AdminAuth())

	v1Admin.GET("/doot", core.Doot())

	// Start server
	if err := http.ListenAndServe(":9091", r); err != nil {
		log.Fatal(err)
	}
}
