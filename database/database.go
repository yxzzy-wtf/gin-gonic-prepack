package database

import (
	"fmt"
	"time"

	"github.com/yxzzy-wtf/gin-gonic-prepack/config"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Database struct {
	*gorm.DB
}

var Db *gorm.DB
var Dialect gorm.Dialector

func InitDialect() gorm.Dialector {
	if config.Config().DbDialect == "sqlite" {
		return sqlite.Open(config.Config().DbUrl)
	} else if config.Config().DbDialect == "postgres" {
		return postgres.New(postgres.Config{
			DSN: fmt.Sprintf("user=%v password=%v dbname=%v port=%v sslmode=disable TimeZone=UTC",
				config.Config().DbUsername, config.Config().DbPasswordSecret, config.Config().DbName,
				config.Config().DbPort),
		})
	} else {
		panic("No valid DB config set up.")
	}
}

func Init() *gorm.DB {
	db, err := gorm.Open(InitDialect(), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	//TODO GORM settings
	database, err := db.DB()
	if err != nil {
		panic(err)
	}

	database.SetMaxIdleConns(10)
	database.SetMaxOpenConns(50)
	database.SetConnMaxLifetime(time.Minute * 30)

	Db = db
	return db
}

func InitTestDb() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("test_prepack.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	//TODO GORM settings
	database, err := db.DB()
	if err != nil {
		panic(err)
	}

	database.SetMaxIdleConns(10)
	database.SetMaxOpenConns(50)
	database.SetConnMaxLifetime(time.Minute * 30)

	Db = db
	return db
}

func GetDb() *gorm.DB {
	return Db
}
