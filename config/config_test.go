package config

import (
	"math/rand"
	"testing"
	"time"
)

type Demo_Config struct {
	Name     string
	Password string
	Url      string
	Port     int
}

func TestConfigFolderExists(t *testing.T) {
	test1, err := ConfigFolderExists(".ssh")
	if err != nil {
		t.Error(err)
	}
	if test1 != "/home/gideon/.ssh" {
		t.Error("SSH folder should exists")
	}

	test2, err := ConfigFolderExists(RandStringRunes(32))
	if err != nil {
		t.Error(err)
	}
	if test2 != "" {
		t.Error("Random folder should not exists but does")
	}
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func TestGenerateYAMLConfigFile(t *testing.T) {
	configFolderName := ".test_config"
	folderPath, err := ConfigFolderExists(configFolderName)
	if err != nil {
		//Could also make the folder here
		t.Error(err)
	}

	configContents := Demo_Config{
		Name:     "superuser",
		Password: "megapassword",
		Url:      "http://github.com",
		Port:     80,
	}

	err = GenerateYAMLConfigFile(folderPath, "config.yml", configContents)
	if err != nil {
		t.Fatal(err)
	}
}
