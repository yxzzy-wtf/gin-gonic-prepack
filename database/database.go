package database

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Database struct {
	*gorm.DB
}

var Db *gorm.DB

func Init() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("prepack.db"), &gorm.Config{})
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
