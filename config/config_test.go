package config

import (
	"testing"
)

func TestAllConfigs(t *testing.T) {
	SingleStackTest(t, "dev", StackConfiguration{
		AllowFreshAdminGeneration: true,
		AdminEmails:               []string{"admin@admin.invalid"},
		AdminHmacEnv:              "ADMIN_HMAC_ENV",
		UserHmacEnv:               "USER_HMAC_ENV",
		AuthedRateLimitConfig:     "ratelimit.auth.json",
		UnauthedRateLimitConfig:   "ratelimit.unauth.json",
	})
}

func SingleStackTest(t *testing.T, stack string, expected StackConfiguration) {
	Config = StackConfiguration{}

	if Config.ConfigLoaded {
		t.Errorf("Config.ConfigLoaded should be false before any processing")
	}

	if len(Config.AdminEmails) > 0 ||
		Config.AdminHmacEnv != "" ||
		Config.UserHmacEnv != "" ||
		Config.AllowFreshAdminGeneration ||
		Config.AuthedRateLimitConfig != "" ||
		Config.UnauthedRateLimitConfig != "" { // Extend this IF for any other config values
		t.Errorf("Config already has values before loading")
	}

	Environment = stack
	LoadConfig()

	if !Config.ConfigLoaded {
		t.Errorf("Config was not set to loaded")
	}

	// Finally test values
	if Config.AllowFreshAdminGeneration != expected.AllowFreshAdminGeneration {
		t.Errorf("AllowFreshAdminGeneration value not set properly")
	}

	for i, email := range Config.AdminEmails {
		if expected.AdminEmails[i] != email {
			t.Errorf("AdminEmails value not set properly, expected %v at %v, was %v", expected.AdminEmails[i], i, email)
		}
	}

	if Config.AdminHmacEnv != expected.AdminHmacEnv {
		t.Errorf("AdminHmacEnv value not set properly")
	}

	if Config.UserHmacEnv != expected.UserHmacEnv {
		t.Errorf("UserHmacEnv value not set properly")
	}

	if Config.AuthedRateLimitConfig != expected.AuthedRateLimitConfig {
		t.Errorf("AuthedRateLimitConfig value not set properly")
	}

	if Config.UnauthedRateLimitConfig != expected.UnauthedRateLimitConfig {
		t.Errorf("UnauthedRateLimitConfig value not set properly")
	}

}
