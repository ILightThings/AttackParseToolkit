package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

//TODO build a config folder function
//TODO build a function that makes a default config file

// Creates a yaml config file from a struct.
func GenerateYAMLConfigFile(configFolderPath string, configFileName string, configContents interface{}) error {

	yamlData, err := yaml.Marshal(&configContents)

	if err != nil {
		return err
	}

	configFilePath := GetConfigFilePath(configFolderPath, configFileName)

	err = os.WriteFile(configFilePath, yamlData, 0644)
	return err

}

// Checks to see if folder exists. If not, creates folder. Returns path if sucessfull.
func CreateConfigFolder(configFolderName string) (string, error) {
	folderPath, err := GetConfigFolderPath(configFolderName)
	if err != nil {
		return "", err
	}

	err = os.Mkdir(folderPath, os.ModePerm)
	if err != nil {
		return "", err
	}

	return folderPath, nil

}

func ConfigFileExists()

// If folder exists, return folderpath, else returns error
func ConfigFolderExists(configFolderName string) (string, error) {
	configFolderPath, err := GetConfigFolderPath(configFolderName)
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(configFolderPath); !os.IsNotExist(err) {
		return configFolderPath, nil
	} else {
		return configFolderPath, err
	}

}

func GetConfigFilePath(configFolderName string, configFileNamestring string) string {
	return filepath.Join(configFolderName, configFileNamestring)
}

func GetConfigFolderPath(configFolderName string) (string, error) {
	if strings.Contains(configFolderName, "/") {
		return "", errors.New("config folder name cannot contain forward /")
	}

	homedir, err := getHomeDir()
	if err != nil {
		return "", err
	}

	configfolder := filepath.Join(homedir, configFolderName)
	return configfolder, nil

}

func getHomeDir() (string, error) {
	dirname, err := os.UserHomeDir()
	return dirname, err
}
