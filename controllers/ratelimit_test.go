package controllers

import (
	"testing"
	"time"
)

func TestBucketBehaviour(t *testing.T) {
	b := bucket{
		rules: &map[string]rule{
			"":                                       {time.Second, 0}, // Deny
			"/1sec5max":                              {time.Second, 5},
			"/2sec1max":                              {time.Second * 2, 1},
			"/wildcard/.+/1sec1max":                  {time.Second, 1},
			"/regex/(test|woot)/1sec2max/[A-Z]{2,3}": {time.Second, 2},
		},
		access: map[string]int{},
	}

	firstTestAutoblocked := []string{
		"willnotwork",
		"/invalidresource",
		"/1sec5max/butThenHasThis",
		"/wildcard/1sec1max",
		"/wildcard//1sec1max",
		"/regex/test/1sec2max/A",
		"/regex/test/1sec2max/aaa",
		"/regex/incorrect /1sec2max/HD",
	}

	for i, fail := range firstTestAutoblocked {
		if b.take(fail) {
			t.Errorf("should have auto-throttled %v: '%v'", i, fail)
		}
	}

	// Test exhausting the whole bucket, all of these calls should return TRUE
	secondTestExhaust := []string{
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/2sec1max",
		"/wildcard/bloop/1sec1max",
		"/regex/woot/1sec2max/FF",
		"/regex/woot/1sec2max/ZAF",
	}

	for i, succeed := range secondTestExhaust {
		if !b.take(succeed) {
			t.Errorf("draining buckets: should have allowed %v: '%v'", i, succeed)
		}
	}

	// Immediately testing this should return false for successful ones
	thirdTestHasExhausted := []string{
		"/1sec5max",
		"/2sec1max",
		"/wildcard/cool-stuff/1sec1max",
		"/regex/woot/1sec2max/JFK",
	}

	for i, exhausted := range thirdTestHasExhausted {
		if b.take(exhausted) {
			t.Errorf("testing exhausted buckets: should have throttled %v: '%v'", i, exhausted)
		}
	}

	// Wait for the smallest duration, 1 second, and test
	time.Sleep(time.Second + time.Millisecond*200)

	fourthTestShouldSucceedAgain := []string{
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/wildcard/yeehaw/1sec1max",
		"/regex/woot/1sec2max/ASD",
		"/regex/test/1sec2max/ZZ",
	}

	for i, succeed := range fourthTestShouldSucceedAgain {
		if !b.take(succeed) {
			t.Errorf("1 sec has elapsed, should allow again %v: '%v'", i, succeed)
		}
	}

	fourthTestShouldStillFail := []string{
		"/2sec1max",
	}

	for i, fail := range fourthTestShouldStillFail {
		if b.take(fail) {
			t.Errorf("1 sec has elapsed, should still not allow %v: '%v'", i, fail)
		}
	}

	time.Sleep(time.Second + time.Millisecond*200)

	fifthTestShouldNowSucceed := fourthTestShouldStillFail

	for i, succeed := range fifthTestShouldNowSucceed {
		if !b.take(succeed) {
			t.Errorf("1 more sec has elapsed, should now allow again %v: '%v'", i, succeed)
		}
	}

}

func TestMegabucketBehaviour(t *testing.T) {
	m := megabucket{
		rules: map[string]rule{
			"":          {time.Second, 0}, // Deny
			"/1sec5max": {time.Second, 5},
			"/2sec1max": {time.Second * 2, 1},
		},
		buckets: map[string]bucket{},
	}

	// User up all for user1
	firstTestUser1Succeed := []string{
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/2sec1max",
	}
	for i, succeed := range firstTestUser1Succeed {
		if !m.take("user1", succeed) {
			t.Errorf("user1 failed to take %v: %v", i, succeed)
		}
	}

	if !m.take("user2", "/1sec5max") {
		t.Errorf("user2 was throttled unfairly when taking /1sec5max")
	}

	if !m.take("user2", "/2sec1max") {
		t.Errorf("user2 was throttled unfairly when taking /2sec1max")
	}

	// Now, user1 and user2 should be getting throttled on /2sec1max
	if m.take("user1", "/2sec1max") {
		t.Errorf("user1 was not throttled on /2sec1max")
	}

	if m.take("user2", "/2sec1max") {
		t.Errorf("user2 was not throttled on /2sec1max")
	}

	// Wait one second, confirm that both can do 5x 1sec5max again
	time.Sleep(time.Second + time.Millisecond*200)

	thirdTestUnblockedBothSucceed := []string{
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
		"/1sec5max",
	}
	for i, succeed := range thirdTestUnblockedBothSucceed {
		if !m.take("user1", succeed) {
			t.Errorf("user1 failed to take %v: %v", i, succeed)
		}
		if !m.take("user2", succeed) {
			t.Errorf("user2 failed to take %v: %v", i, succeed)
		}
	}

}
