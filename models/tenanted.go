package models

import (
	"errors"

	"github.com/google/uuid"

	"gorm.io/gorm"
)

type Tenanted struct {
	Base
	Tenant uuid.UUID `gorm:"index;<-:create"`
}

func (t *Tenanted) BeforeCreate(scope *gorm.DB) error {
	if t.Tenant == uuid.Nil {
		return errors.New("cannot save an untenanted object")
	}
	return nil
}
