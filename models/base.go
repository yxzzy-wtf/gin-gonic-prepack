package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Base struct {
	Uid     uuid.UUID `gorm:"type:uuid;primary_key;"`
	Created time.Time
	Updated time.Time
	Deleted time.Time `sql:"index"`
	Tenant  uuid.UUID
}

func (b *Base) BeforeCreate(scope *gorm.DB) error {
	b.Uid = uuid.New()
	b.Created = time.Now()
	return nil
}

func (b *Base) BeforeSave(tx *gorm.DB) error {
	b.Updated = time.Now()
	return nil
}

func (b *Base) Delete() {
	b.Deleted = time.Now()
}
