package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Base struct {
	Uid     uuid.UUID `gorm:"type:uuid;primary_key;"`
	Created time.Time
	Updated time.Time
	Deleted time.Time `sql:"index"`
	Tenant  uuid.UUID `sql:"index"`
}

func (b *Base) BeforeCreate(scope *gorm.DB) error {
	b.Uid = uuid.New()
	b.Created = time.Now()
	return nil
}

func (b *Base) BeforeSave(scope *gorm.DB) error {
	if b.Tenant == uuid.Nil {
		return errors.New("cannot save an untenanted object")
	}

	b.Updated = time.Now()
	return nil
}

func (b *Base) Delete() {
	b.Deleted = time.Now()
}
