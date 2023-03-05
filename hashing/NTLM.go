package hashing

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/ILightThings/AttackParseToolkit/encodeutil"
)

/*
PSUDO CODE
https://blog.smallsec.ca/ntlm-challenge-response/


NTLMv2 Hash     = HMAC-MD5(NT Hash, uppercase(username) + target)
NTLMv2 Goodies  = HMAC-MD5(NTLMv2 Hash, challenge + blob)
NTLMv2 Response = NTLMv2 Goodies + blob


*/

//USERNAME https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/%5bMS-NLMP%5d.pdf 3.3.2
// user is upper case, domain is uppercase contactinated
//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
//https://en.hackndo.com/ntlm-relay/
//https://github.com/fortra/impacket/blob/f4b848fa27654ca95bc0f4c73dbba8b9c2c9f30a/impacket/ntlm.py#L894

func GenNTOWFv2(user string, domain string, password string, ntlmhash []byte) ([]byte, error) {

	if len(ntlmhash) == 0 {
		ntlmhash = ToNTHash(password)
	}

	//Username needs to be encoded to UTF-16LE
	usernameByte, err := encodeutil.EncodeToUTF16(strings.ToUpper(user))
	if err != nil {
		return []byte{}, err
	}

	domainByte, err := encodeutil.EncodeToUTF16(domain)
	if err != nil {
		return []byte{}, err
	}

	usernameTargetBlob := append(usernameByte, domainByte...)
	fmt.Printf("%+v", usernameTargetBlob)

	stage1, err := genHMACMD5(ntlmhash, []byte(usernameTargetBlob))
	if err != nil {
		return []byte{}, err
	}

	return stage1, nil

}

// ntProofStr
// Hash or Password
func GenerateNTLMv2ChallengeProof(challenge []byte, password string, ntlmhash []byte, username string, domain string, blob []byte) ([]byte, error) {

	NTFOv2, err := GenNTOWFv2(username, domain, password, ntlmhash)
	if err != nil {
		return []byte{}, err
	}

	challengeBlob := append(challenge, blob...)

	stage2, err := genHMACMD5(NTFOv2, challengeBlob)

	if err != nil {
		return []byte{}, err
	}

	return stage2, nil

}

func genHMACMD5(key []byte, n []byte) ([]byte, error) {
	hasher := hmac.New(md5.New, key)
	_, err := hasher.Write(n)
	return hasher.Sum(nil), err
}

type NTLMSSPObj struct {
	NTMLSSPMessageType []byte //4 bytes, offset 8
	TargetName         []byte // 8 bytes, offset 12

}

func ParseNTLMSSP(NTLMSSP []byte) (NTLMSSPObj, error) {
	var NTSSPObj NTLMSSPObj

	NTLMSSP_Identifyer := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}
	if !bytes.Equal(NTLMSSP[0:8], NTLMSSP_Identifyer) {
		return NTSSPObj, errors.New("NTLMSSP Header is not correct")

	}

	TargetNameHeader := NTLMSSP[12:20]
	TargetNameLen := TargetNameHeader[0:2]

	//Not needed
	//TargetNameMaxLen := TargetNameHeader[2:4]
	TargetNameBufferOffset := TargetNameHeader[4:8]
	fmt.Printf("%+v\n", TargetNameBufferOffset)
	fmt.Println(binary.LittleEndian.Uint16(TargetNameBufferOffset))
	NTSSPObj.TargetName = NTLMSSP[binary.LittleEndian.Uint16(TargetNameBufferOffset) : binary.LittleEndian.Uint16(TargetNameBufferOffset)+binary.LittleEndian.Uint16(TargetNameLen)]

	return NTSSPObj, nil

}
