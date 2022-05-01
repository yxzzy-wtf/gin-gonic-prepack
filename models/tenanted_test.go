package models

import "testing"

func TestCannotCreateUntenanted(t *testing.T) {
	tnt := Tenanted{}

	if err := tnt.BeforeCreate(nil); err == nil {
		t.Errorf("allowed creation of Tenanted model without Tenant value")
	}
}
