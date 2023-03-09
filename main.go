package main

import (
	"fmt"
	"log"

	"github.com/ILightThings/AttackParseToolkit/parse"
)

//TODO, turn this into a struct that notes failed parses

func main() {
	cred, err := parse.ParseParameterCredentialImpacket("light.local/ilightthings.local:P@assword")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v", cred)

}
