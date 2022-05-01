package util

import (
	"testing"
)

func TestParseJwt(t *testing.T) {
	premadeJwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbTEiOiJjbGFpbTEtdmFsIiwiY2xhaW0yIjoyMjJ9.n1rVLigY5Q6CNKqcGD38i27dqytY2qaWhXexq6PKyIY"
	premadeHmac := []byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}

	parsed, err := ParseJwt(premadeJwt, premadeHmac)
	if err != nil {
		t.Errorf("should not fail parsing JWT")
	}

	if parsed["claim1"] != "claim1-val" {
		t.Errorf("did not contain expected value for claim1, %v", parsed)
	}

	if parsed["claim2"] != 222.0 {
		t.Errorf("did not contain expected value for claim2, %v", parsed)
	}

}
