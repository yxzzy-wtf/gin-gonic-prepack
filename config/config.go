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
}

var Environment = os.Getenv("STACK_ENVIRONMENT")

var Config = StackConfiguration{}

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
	if err := dec.Decode(&Config); err != nil {
		panic(err)
	}

	Config.ConfigLoaded = true

	log.Printf("Loaded Config for stack " + Environment)
}
