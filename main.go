package main

import (
	"log"
	"net/http"

	"github.com/yxzzy-wtf/gin-gonic-prepack/controllers/core"
	"github.com/yxzzy-wtf/gin-gonic-prepack/database"
	"github.com/yxzzy-wtf/gin-gonic-prepack/models"

	"github.com/gin-gonic/gin"
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
	v1.GET("/doot", core.Doot())

	// Standard user login
	v1.POST("/signup", core.UserSignup())
	v1.POST("/login", core.UserLogin())
	v1Sec := v1.Group("/sec", core.UserAuth())

	v1Sec.GET("/doot", core.Doot())

	// Administrative login
	v1.POST("/admin", core.AdminLogin())
	v1Admin := v1.Group("/adm", core.AdminAuth())

	v1Admin.GET("/doot", core.Doot())

	// Start server
	if err := http.ListenAndServe(":9091", r); err != nil {
		log.Fatal(err)
	}
}
