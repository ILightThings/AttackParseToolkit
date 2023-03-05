package hashing

import (
	"bytes"
	"testing"
)

func TestGenerateNTLMv2ChallengeProof(t *testing.T) {

	//Timestamp 80ce5e54ca4ed901

	var bytebuffer = [][]byte{
		//responseServerVersion
		[]byte{0x01},

		//hiresponseServerVersion
		[]byte{0x01},

		//Z6
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},

		//TIMESTAMP
		[]byte{0x00, 0x98, 0x5b, 0x1c, 0x6b, 0x4f, 0xd9, 0x01},

		//Client challenge 71386c7a71335532
		//TODO, What the hell generates this?
		[]byte{0x46, 0x4e, 0x73, 0x72, 0x32, 0x33, 0x78, 0x45},

		//Z4
		[]byte{0x00, 0x00, 0x00, 0x00},

		//Server Name
		// This is the entire output of the TARGET INFO field
		[]byte{0x01, 0x00, 0x10, 0x00, 0x41, 0x00, 0x57, 0x00, 0x69, 0x00, 0x46, 0x00, 0x52, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x7a, 0x00, 0x03, 0x00, 0x10, 0x00, 0x41, 0x00, 0x57, 0x00, 0x69, 0x00, 0x46, 0x00, 0x52, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x7a, 0x00, 0x02, 0x00, 0x10, 0x00, 0x70, 0x00, 0x75, 0x00, 0x67, 0x00, 0x49, 0x00, 0x6c, 0x00, 0x6a, 0x00, 0x54, 0x00, 0x73, 0x00, 0x04, 0x00, 0x10, 0x00, 0x70, 0x00, 0x75, 0x00, 0x67, 0x00, 0x49, 0x00, 0x6c, 0x00, 0x6a, 0x00, 0x54, 0x00, 0x73, 0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x98, 0x5b, 0x1c, 0x6b, 0x4f, 0xd9, 0x01, 0x09, 0x00, 0x1a, 0x00, 0x63, 0x00, 0x69, 0x00, 0x66, 0x00, 0x73, 0x00, 0x2f, 0x00, 0x41, 0x00, 0x57, 0x00, 0x69, 0x00, 0x46, 0x00, 0x52, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00},

		//Z4
		[]byte{0x00, 0x00, 0x00, 0x00},
	}

	SchallTemp := []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0x5b, 0x1c, 0x6b, 0x4f, 0xd9, 0x01, 0x46, 0x4e, 0x73, 0x72, 0x32, 0x33, 0x78, 0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x41, 0x00, 0x57, 0x00, 0x69, 0x00, 0x46, 0x00, 0x52, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x7a, 0x00, 0x03, 0x00, 0x10, 0x00, 0x41, 0x00, 0x57, 0x00, 0x69, 0x00, 0x46, 0x00, 0x52, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x7a, 0x00, 0x02, 0x00, 0x10, 0x00, 0x70, 0x00, 0x75, 0x00, 0x67, 0x00, 0x49, 0x00, 0x6c, 0x00, 0x6a, 0x00, 0x54, 0x00, 0x73, 0x00, 0x04, 0x00, 0x10, 0x00, 0x70, 0x00, 0x75, 0x00, 0x67, 0x00, 0x49, 0x00, 0x6c, 0x00, 0x6a, 0x00, 0x54, 0x00, 0x73, 0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x98, 0x5b, 0x1c, 0x6b, 0x4f, 0xd9, 0x01, 0x09, 0x00, 0x1a, 0x00, 0x63, 0x00, 0x69, 0x00, 0x66, 0x00, 0x73, 0x00, 0x2f, 0x00, 0x41, 0x00, 0x57, 0x00, 0x69, 0x00, 0x46, 0x00, 0x52, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	NTLMChallenge := []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}

	var SecurityBlob []byte
	for _, v := range bytebuffer {
		SecurityBlob = append(SecurityBlob, v...)
	}
	ttt := append(NTLMChallenge, SecurityBlob...)

	if !bytes.Equal(SchallTemp, ttt) {
		t.Fatalf("Security Blob(%d) and Actual(%d) dont match\nExpected\n%#v\nactual:\n%#v", len(SchallTemp), len(ttt), SchallTemp, ttt)
	}

	//cifs/KeWsxiRd
	//TargetName := []byte{0x63, 0x00, 0x69, 0x00, 0x66, 0x00, 0x73, 0x00, 0x2f, 0x00, 0x4b, 0x00, 0x65, 0x00, 0x57, 0x00, 0x73, 0x00, 0x78, 0x00, 0x69, 0x00, 0x52, 0x00, 0x64, 0x00}

	//DOMAIN LIGHT.LOCAL
	//Might also be the target
	Domain := "light.local"
	username := "ilightthings"

	passwordhash := ToNTHash("password")

	//light.local/ilightthings:password
	ExpectedProofString := []byte{0xc1, 0x21, 0xdd, 0x0a, 0xcb, 0xff, 0x24, 0x28, 0xcc, 0x0c, 0xe9, 0x7a, 0x23, 0x4f, 0x54, 0x68}

	proof, err := GenerateNTLMv2ChallengeProof(NTLMChallenge, "", passwordhash, username, Domain, SecurityBlob)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(ExpectedProofString, proof) {
		t.Errorf("proof dont match\nExpected\n%+v\ngot:\n%+v", ExpectedProofString, proof)

	}

	// 8d27c753d9b37df328ce0de32d333ecb010100000000000080ce5e54ca4ed90171386c7a7133553200000000010010004b006500570073007800690052006400030010004b006500570073007800690052006400020010007a006b00620066007700790051005200040010007a006b006200660077007900510052000700080080ce5e54ca4ed90109001a0063006900660073002f004b0065005700730078006900520064000000000000000000
	//Responce := []byte{0x8d, 0x27, 0xc7, 0x53, 0xd9, 0xb3, 0x7d, 0xf3, 0x28, 0xce, 0x0d, 0xe3, 0x2d, 0x33, 0x3e, 0xcb, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xce, 0x5e, 0x54, 0xca, 0x4e, 0xd9, 0x01, 0x71, 0x38, 0x6c, 0x7a, 0x71, 0x33, 0x55, 0x32, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x4b, 0x00, 0x65, 0x00, 0x57, 0x00, 0x73, 0x00, 0x78, 0x00, 0x69, 0x00, 0x52, 0x00, 0x64, 0x00, 0x03, 0x00, 0x10, 0x00, 0x4b, 0x00, 0x65, 0x00, 0x57, 0x00, 0x73, 0x00, 0x78, 0x00, 0x69, 0x00, 0x52, 0x00, 0x64, 0x00, 0x02, 0x00, 0x10, 0x00, 0x7a, 0x00, 0x6b, 0x00, 0x62, 0x00, 0x66, 0x00, 0x77, 0x00, 0x79, 0x00, 0x51, 0x00, 0x52, 0x00, 0x04, 0x00, 0x10, 0x00, 0x7a, 0x00, 0x6b, 0x00, 0x62, 0x00, 0x66, 0x00, 0x77, 0x00, 0x79, 0x00, 0x51, 0x00, 0x52, 0x00, 0x07, 0x00, 0x08, 0x00, 0x80, 0xce, 0x5e, 0x54, 0xca, 0x4e, 0xd9, 0x01, 0x09, 0x00, 0x1a, 0x00, 0x63, 0x00, 0x69, 0x00, 0x66, 0x00, 0x73, 0x00, 0x2f, 0x00, 0x4b, 0x00, 0x65, 0x00, 0x57, 0x00, 0x73, 0x00, 0x78, 0x00, 0x69, 0x00, 0x52, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

}

/*

[*] Incoming connection (192.168.1.197,57846)
[*] AUTHENTICATE_MESSAGE (light.local\ilightthings,)
[*] User \ilightthings authenticated successfully
[*] ilightthings::light.local:aaaaaaaaaaaaaaaa:8d27c753d9b37df328ce0de32d333ecb:010100000000000080ce5e54ca4ed90171386c7a7133553200000000010010004b006500570073007800690052006400030010004b006500570073007800690052006400020010007a006b00620066007700790051005200040010007a006b006200660077007900510052000700080080ce5e54ca4ed90109001a0063006900660073002f004b0065005700730078006900520064000000000000000000
[*] Closing down connection (192.168.1.197,57846)

username::domain:challengestring:Proofstring:ChallengeParamteres


*/

func Test_genHMACMD5(t *testing.T) {
	stringToHash := "password"

	//https://gchq.github.io/CyberChef/#recipe=NT_Hash()From_Hex('Auto')To_Hex('0x%20with%20comma',0/breakpoint)&input=cGFzc3N3b3JkMTIz
	//NT hash for password123
	hashKey := []byte{0x72, 0x7e, 0xf0, 0xd8, 0x08, 0x9e, 0xb6, 0x55, 0xbd, 0xe2, 0xba, 0x4d, 0x04, 0x99, 0xe4, 0xf9}

	//https://gchq.github.io/CyberChef/#recipe=HMAC(%7B'option':'Hex','string':'727EF0D8089EB655BDE2BA4D0499E4F9'%7D,'MD5')From_Hex('Auto')To_Hex('0x%20with%20comma',0)&input=cGFzc3dvcmQ
	//536f5188de82d1ebafaa1db372dcf564
	expectedOut := []byte{0x53, 0x6f, 0x51, 0x88, 0xde, 0x82, 0xd1, 0xeb, 0xaf, 0xaa, 0x1d, 0xb3, 0x72, 0xdc, 0xf5, 0x64}

	actualOut, err := genHMACMD5(hashKey, []byte(stringToHash))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(expectedOut, actualOut) {
		t.Errorf("unexpected result.\nShould be:\n%+v\nActually\n%+v", expectedOut, actualOut)
	}

}

//ilightthings::light.local:aaaaaaaaaaaaaaaa:8d27c753d9b37df328ce0de32d333ecb:010100000000000080ce5e54ca4ed90171386c7a7133553200000000010010004b006500570073007800690052006400030010004b006500570073007800690052006400020010007a006b00620066007700790051005200040010007a006b006200660077007900510052000700080080ce5e54ca4ed90109001a0063006900660073002f004b0065005700730078006900520064000000000000000000

func TestGenNTOWFv2(t *testing.T) {
	user := "ilightthings"
	domain := "light.local"
	password := "password"
	var hash []byte

	expectedOut := []byte{0x8d, 0x19, 0x78, 0x8c, 0x29, 0xc5, 0x77, 0x78, 0x5d, 0xa0, 0x34, 0xc0, 0xa9, 0x19, 0xb8, 0x82}
	actualOut, err := GenNTOWFv2(user, domain, password, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expectedOut, actualOut) {
		t.Errorf("unexpected result.\nShould be:\n%+v\nActually\n%+v", expectedOut, actualOut)
	}
}

func TestParseNTLMSSP(t *testing.T) {
	testcase := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x38, 0x00, 0x00, 0x00, 0x05, 0x02, 0x8a, 0xa2, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x60, 0x00, 0x48, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x70, 0x00, 0x75, 0x00, 0x67, 0x00, 0x49, 0x00, 0x6c, 0x00, 0x6a, 0x00, 0x54, 0x00, 0x73, 0x00, 0x01, 0x00, 0x10, 0x00, 0x41, 0x00, 0x57, 0x00, 0x69, 0x00, 0x46, 0x00, 0x52, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x7a, 0x00, 0x03, 0x00, 0x10, 0x00, 0x41, 0x00, 0x57, 0x00, 0x69, 0x00, 0x46, 0x00, 0x52, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x7a, 0x00, 0x02, 0x00, 0x10, 0x00, 0x70, 0x00, 0x75, 0x00, 0x67, 0x00, 0x49, 0x00, 0x6c, 0x00, 0x6a, 0x00, 0x54, 0x00, 0x73, 0x00, 0x04, 0x00, 0x10, 0x00, 0x70, 0x00, 0x75, 0x00, 0x67, 0x00, 0x49, 0x00, 0x6c, 0x00, 0x6a, 0x00, 0x54, 0x00, 0x73, 0x00, 0x07, 0x00, 0x08, 0x00, 0x80, 0x82, 0x2a, 0x83, 0x66, 0x4f, 0xd9, 0x01, 0x00, 0x00, 0x00, 0x00}

	obj, err := ParseNTLMSSP(testcase)
	if err != nil {
		t.Fatal(err)
	}

	//pugIljTs
	expectedTargetNameBytes := []byte{0x70, 0x00, 0x75, 0x00, 0x67, 0x00, 0x49, 0x00, 0x6c, 0x00, 0x6a, 0x00, 0x54, 0x00, 0x73, 0x00}
	//targetNameDecoded := "pugIljTs"

	if !bytes.Equal(expectedTargetNameBytes, obj.TargetName) {
		t.Errorf("unexpected result.\nShould be:\n%+v\nActually\n%+v", expectedTargetNameBytes, obj.TargetName)
	}

}
