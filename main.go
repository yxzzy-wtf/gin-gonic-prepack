package main

import (
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/yxzzy-wtf/gin-gonic-prepack/config"
	"github.com/yxzzy-wtf/gin-gonic-prepack/controllers"
	"github.com/yxzzy-wtf/gin-gonic-prepack/controllers/core"
	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
	"github.com/yxzzy-wtf/gin-gonic-prepack/models"
	"github.com/yxzzy-wtf/gin-gonic-prepack/scheduled"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func Migrate(g *gorm.DB) {
	g.AutoMigrate(&models.User{})
	g.AutoMigrate(&models.Admin{})
	g.AutoMigrate(&models.TotpUsage{})
}

// @title Go-Gin Prepack
// @version 1
// @BasePath /v1
func main() {
	config.LoadConfig()

	db := database.Init()
	Migrate(db)

	// Scheduled tasks
	go scheduled.ExecuteImmediatelyAndSchedule(func() (string, time.Duration) {
		err := database.Db.Where("used < ?", time.Now().Add(-24*time.Hour)).Delete(&models.TotpUsage{}).Error
		if err != nil {
			return "purge failed, trying again in one hour: " + err.Error(), time.Hour
		}
		return "purged old TOTP usages", time.Hour * 24
	})

	r := gin.Default()

	// Fresh admin functionality
	if config.Config.AllowFreshAdminGeneration {
		var adminCount int64
		database.Db.Model(models.Admin{}).Count(&adminCount)

		if adminCount == 0 {
			randUri := uuid.New()
			r.POST("/"+randUri.String(), core.StarterAdmin())
		}
	}

	v1 := r.Group("/v1")

	v1.GET("/doot", controllers.UnauthRateLimit(), core.Doot())

	// Standard user signup, verify, login and forgot/reset pw
	v1.POST("/signup", controllers.UnauthRateLimit(), core.UserSignup())
	v1.POST("/login", controllers.UnauthRateLimit(), core.UserLogin())
	v1.GET("/verify", controllers.UnauthRateLimit(), core.UserVerify())
	v1.POST("/forgot", controllers.UnauthRateLimit(), core.UserForgotPassword())
	v1.POST("/reset", controllers.UnauthRateLimit(), core.UserResetForgottenPassword())

	v1Sec := v1.Group("/sec", core.UserAuth(), controllers.AuthedRateLimit())

	v1Sec.GET("/doot", core.Doot())
	v1Sec.GET("/2fa-doot", core.LiveTwoFactor(), core.Doot())

	// Administrative login
	v1.POST("/admin", controllers.UnauthRateLimit(), core.AdminLogin())
	v1Admin := v1.Group("/adm", core.AdminAuth())

	v1Admin.GET("/doot", core.Doot())
	v1Admin.GET("/2fa-doot", core.LiveTwoFactor(), core.Doot())

	// Start server
	if err := http.ListenAndServe(":9091", r); err != nil {
		log.Fatal(err)
	}
}
