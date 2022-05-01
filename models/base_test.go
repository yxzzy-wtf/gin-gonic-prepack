package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOnCreateNewUUID(t *testing.T) {
	now := time.Now()
	b := Base{}
	b.BeforeCreate(nil)

	if b.Uid == uuid.Nil {
		t.Errorf("did not generate uuid BeforeCreate")
	}

	if b.Created.IsZero() {
		t.Errorf("did not set created time")
	}

	if !b.Created.After(now) {
		t.Errorf("created date should be after %v, was %v", now, b.Created)
	}

	if !b.Updated.IsZero() {
		t.Errorf("updated date already set to %v", b.Updated)
	}

	if !b.Deleted.IsZero() {
		t.Errorf("deleted date already set to %v", b.Updated)
	}
}

func TestOnSaveUpdateDate(t *testing.T) {
	now := time.Now()
	b := Base{}
	b.BeforeSave(nil)

	if !b.Updated.After(now) {
		t.Errorf("updated date should be updated to after %v, is %v", now, b.Updated)
	}
}

func TestDeleteSetsTime(t *testing.T) {
	now := time.Now()
	b := Base{}
	b.Delete()

	if !b.Deleted.After(now) {
		t.Errorf("updated date should be updated to after %v, is %v", now, b.Updated)
	}
}
