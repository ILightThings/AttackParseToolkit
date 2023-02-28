package parse_cli

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseParameterCredentialImpacket(t *testing.T) {

	//Inital test
	test1, err := ParseParameterCredentialImpacket("lamp.local/ilightthings:Lampshade!!")
	if err != nil {
		t.Error(err)
	}
	result1 := ImpacketAuth{Username: "ilightthings", Password: "Lampshade!!", Domain: "lamp.local"}

	if !cmp.Equal(test1, result1) {
		t.Errorf("Test1 not equal to Result1\n%v\n%v", test1, result1)
	}

	//@ in the password
	test2, err := ParseParameterCredentialImpacket("github.com/superuser:ADVANCEDP@ASS")
	result2 := ImpacketAuth{Username: "superuser", Password: "ADVANCEDP@ASS", Domain: "github.com"}

	if err != nil {
		t.Error(err)
	}

	if !cmp.Equal(test2, result2) {
		t.Errorf("Test2 not equal to Result2\n%v\n%v", test2, result2)
	}

	//No password,no TLD in domain
	test3, err := ParseParameterCredentialImpacket("worldwide/earth")
	result3 := ImpacketAuth{Username: "earth", Password: "", Domain: "worldwide"}

	if err != nil {
		t.Error(err)
	}

	if !cmp.Equal(test3, result3) {
		t.Errorf("Test3 not equal to Result3\n%v\n%v", test3, result3)
	}

	// Just a username
	test4, err := ParseParameterCredentialImpacket("Eviluser")
	if err != nil {
		t.Error(err)
	}
	result4 := ImpacketAuth{Username: "Eviluser"}
	if !cmp.Equal(test4, result4) {
		t.Errorf("Test4 not equal to Result4\n%v\n%v", test4, result4)
	}

	//Extraslashes
	badstring := "domain/user//:password"
	test5, err := ParseParameterCredentialImpacket(badstring)
	if err != nil {
		t.Error(err)
	}
	result5 := ImpacketAuth{Username: "user//", Password: "password", Domain: "domain"}
	if !cmp.Equal(test5, result5) {
		t.Errorf("Test5 not equal to Result5\n%v\n%v", test5, result5)
	}

}
