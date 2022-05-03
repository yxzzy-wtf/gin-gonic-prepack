package config

import (
	"encoding/json"
	"os"
)

type StackConfiguration struct {
	ConfigLoaded              bool
	AllowFreshAdminGeneration bool
	AdminEmails               []string
	AdminHmacEnv              string
	UserHmacEnv               string
}

var Config = StackConfiguration{}

func LoadConfig() {
	file, _ := os.Open("conf.json")
	defer file.Close()
	dec := json.NewDecoder(file)
	if err := dec.Decode(&Config); err != nil {
		panic(err)
	}

	Config.ConfigLoaded = true
}
