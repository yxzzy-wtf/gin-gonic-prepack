package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Base struct {
	Uid     uuid.UUID `gorm:"type:uuid;primary_key;<-:create"`
	Created time.Time `gorm:"<-:create"`
	Updated time.Time
	Deleted time.Time `gorm:"index"`
}

func (b *Base) BeforeCreate(scope *gorm.DB) error {
	b.Uid = uuid.New()
	b.Created = time.Now()
	return nil
}

func (b *Base) BeforeSave(scope *gorm.DB) error {
	b.Updated = time.Now()
	return nil
}

func (b *Base) Delete() {
	b.Deleted = time.Now()
}
