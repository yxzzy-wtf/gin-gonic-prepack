package config

import (
	"encoding/json"
	"log"
	"os"
)

type StackConfiguration struct {
	ConfigLoaded bool

	AllowFreshAdminGeneration bool
	AdminEmails               []string
	AdminHmacEnv              string
	UserHmacEnv               string
	AuthedRateLimitConfig     string
	UnauthedRateLimitConfig   string

	DbDialect        string
	DbUsername       string
	DbPasswordSecret string
	DbUrl            string
	DbPort           string
	DbName           string
}

var Environment = os.Getenv("STACK_ENVIRONMENT")

var configInternal = StackConfiguration{}

func Config() StackConfiguration {
	return configInternal
}

func GetConfigPath(filename string) string {
	if Environment == "" {
		Environment = "dev"
	}
	return Environment + "/" + filename
}

func LoadConfig() {
	file, err := os.Open(GetConfigPath("conf.json"))
	if err != nil {
		panic(err)
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	if err := dec.Decode(&configInternal); err != nil {
		panic(err)
	}

	configInternal.ConfigLoaded = true

	log.Printf("Loaded Config for stack " + Environment)
}
