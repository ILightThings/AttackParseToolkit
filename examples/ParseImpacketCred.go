package examples

import (
	"fmt"
	"log"

	"github.com/ILightThings/AttackParseToolkit/parse"
)

func main() {
	cred, err := parse.ParseParameterCredentialImpacket("light.local/ilightthings.local:P@assword")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v", cred)
	//{Username:ilightthings.local Password:P@assword Domain:light.local}

}
