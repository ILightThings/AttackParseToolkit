package hashing

import (
	"bytes"
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

//TODO build func GenLMOWFv1 for NTLMv1 support

// LOL I know its the same as GenNTOWFv2 but shutup
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
func GenLMOWFv2(user string, domain string, password string, ntlmhash []byte) ([]byte, error) {
	stage1, err := GenNTOWFv2(user, domain, password, ntlmhash)
	return stage1, err

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

type NTLMSSP_Challenge struct {
	NTLMSSP_identifier []byte // 8 bytes offset 0
	NTLM_Message_Type  []byte // 4 bytes, offset 8
	TargetName         []byte // 8 bytes, offset 12
	NetgotiateFlags    []byte // 4 bytes, offset 20
	ServerChallenge    []byte // 8 bytes, offset 24
	Reserver           []byte // 8 bytes, offset 32
	TargetInfo         []byte // 8 bytes, offset 40
	Version            []byte // 8 bytes, offset 48
}

// Prints a human readble verson of the NTLMSSP_Challenge to the console
func (a *NTLMSSP_Challenge) Readable() error {
	pr_TargetName, err := encodeutil.DecodeUTF16leBytes(a.NTLM_Message_Type)
	if err != nil {
		return err
	}

	fmt.Printf("Target Name %s\n", pr_TargetName)

	fmt.Println("Flags:")
	flags := binary.LittleEndian.Uint32(a.NetgotiateFlags)
	flagsReadable := getHumanNegoFlagNames(flags)
	for _, x := range flagsReadable {
		fmt.Println(x)
	}

	fmt.Printf("\nServer Challenge: %#v\n", a.ServerChallenge)

	//targetInfo_PR :=

	versionParse, err := getVersion(a.Version)
	if err != nil {
		return err
	}

	fmt.Printf("Version Code: %s\n", versionParse.HumanString())

	return nil

}

// Parses the NTLMSSP_Challenge to a NTLMSSP_Challenge struct
// TODO implement the getByteLocation into this parser to make it easier to read
func ParseNTLMSSP_Challenge(NTLMSSP_Challenge_Bytes []byte) (NTLMSSP_Challenge, error) {
	var NTSSPObj NTLMSSP_Challenge

	NTLMSSP_Identifyer := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}
	if !bytes.Equal(NTLMSSP_Challenge_Bytes[0:8], NTLMSSP_Identifyer) {
		return NTSSPObj, errors.New("NTLMSSP Header is not correct")

	}

	//TODO, each of these headers should be a property of the NTLMSSPObj
	//TODO, rename the NTLMSSPobj to NTLMSSPChallenge

	//TargetName
	TargetNameHeader := NTLMSSP_Challenge_Bytes[12:20]
	TargetNameLen := TargetNameHeader[0:2]
	//Not needed
	//TargetNameMaxLen := TargetNameHeader[2:4]
	TargetNameBufferOffset := TargetNameHeader[4:8]
	fmt.Printf("%+v\n", TargetNameBufferOffset)
	fmt.Println(binary.LittleEndian.Uint16(TargetNameBufferOffset))
	NTSSPObj.TargetName = NTLMSSP_Challenge_Bytes[binary.LittleEndian.Uint16(TargetNameBufferOffset) : binary.LittleEndian.Uint16(TargetNameBufferOffset)+binary.LittleEndian.Uint16(TargetNameLen)]

	//Flags
	NTSSPObj.NetgotiateFlags = NTLMSSP_Challenge_Bytes[20:24]

	//Server Challenge
	NTSSPObj.ServerChallenge = NTLMSSP_Challenge_Bytes[24:32]

	//TargetInfo
	TargetInfoHeader := NTLMSSP_Challenge_Bytes[40:48]
	TargetInfoLen := TargetInfoHeader[0:2]
	//Not Needed
	//TargetInfoLenMax := TargetInfoHeader[2:4]
	TargetInfoOffset := TargetInfoHeader[4:8]
	NTSSPObj.TargetInfo = NTLMSSP_Challenge_Bytes[binary.LittleEndian.Uint16(TargetInfoOffset) : binary.LittleEndian.Uint16(TargetInfoOffset)+binary.LittleEndian.Uint16(TargetInfoLen)]

	//Version
	NTSSPObj.Version = NTLMSSP_Challenge_Bytes[48:56]

	return NTSSPObj, nil

}

type NTLMSSP_Auth struct {
	NTLMSSP_identifier   []byte // 8 bytes, offset 0
	NTLM_Message_Type    []byte // 4 bytes, offset 8
	Lan_Manager_Response []byte // 8 bytes, offset 12
	NTLM_Response        []byte // 8 bytes, offset 20
	Domain_name          []byte // 8 bytes, offset 28
	User_name            []byte // 8 bytes, offset 36
	Host_name            []byte // 8 bytes, offset 44
	Session_Key          []byte // 8 bytes, offset 52
	Negotiate_Flags      []byte // 4 bytes, offset 56
	Version              []byte // 8 bytes, offset 60 //that SHOULD be populated only when the NTLMSSP_NEGOTIATE_VERSION flag is set in the NegotiateFlags field
	MIC                  []byte // 8 bytes, offset 68 //
}

func (a *NTLMSSP_Auth) Readable() {

}

func ParseNTLMSSP_Auth(NTLMSSP_Auth_Bytes []byte) (NTLMSSP_Auth, error) {

	var NTSSPObj NTLMSSP_Auth

	NTLMSSP_Identifyer := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}
	if !bytes.Equal(NTLMSSP_Auth_Bytes[0:8], NTLMSSP_Identifyer) {
		return NTSSPObj, errors.New("NTLMSSP Header is not correct")
	}

	NTSSPObj.NTLM_Message_Type = NTLMSSP_Auth_Bytes[8:12]

	LanResponceFields := NTLMSSP_Auth_Bytes[12:20]
	lmStart, lmEnd := getByteLocation(LanResponceFields)
	NTSSPObj.Lan_Manager_Response = NTLMSSP_Auth_Bytes[lmStart:lmEnd]

	NtChallengeResponseFields := NTLMSSP_Auth_Bytes[20:28]
	NtChallStart, NtChallEnd := getByteLocation(NtChallengeResponseFields)
	NTSSPObj.NTLM_Response = NTLMSSP_Auth_Bytes[NtChallStart:NtChallEnd]

	DomainNameFields := NTLMSSP_Auth_Bytes[28:36]
	DomainNameStart, DomainNameEnd := getByteLocation(DomainNameFields)
	NTSSPObj.Domain_name = NTLMSSP_Auth_Bytes[DomainNameStart:DomainNameEnd]

	UserNameFields := NTLMSSP_Auth_Bytes[36:44]
	UserNameStart, UsernameEnd := getByteLocation(UserNameFields)
	NTSSPObj.User_name = NTLMSSP_Auth_Bytes[UserNameStart:UsernameEnd]

	WorkstationFields := NTLMSSP_Auth_Bytes[44:52]
	WorkstationStart, WorkStationEnd := getByteLocation(WorkstationFields)
	NTSSPObj.Host_name = NTLMSSP_Auth_Bytes[WorkstationStart:WorkStationEnd]

	EncryptedRandomSessionKeyFields := NTLMSSP_Auth_Bytes[52:60]
	SessionKeyStart, SessionKeyEnd := getByteLocation(EncryptedRandomSessionKeyFields)
	NTSSPObj.Session_Key = NTLMSSP_Auth_Bytes[SessionKeyStart:SessionKeyEnd]

	NTSSPObj.Negotiate_Flags = NTLMSSP_Auth_Bytes[60:64]

	flags := binary.LittleEndian.Uint32(NTSSPObj.Negotiate_Flags)

	//TODO MIC and Version fields are dependant on the Flags that require them.

	if flags&negotiateFlagNTLMSSPNEGOTIATEVERSION == negotiateFlagNTLMSSPNEGOTIATEVERSION {
		NTSSPObj.Version = NTLMSSP_Auth_Bytes[64:72]
		if flags&negotiateFlagNTLMSSPNEGOTIATESIGN == negotiateFlagNTLMSSPNEGOTIATESIGN {
			NTSSPObj.MIC = NTLMSSP_Auth_Bytes[72:88]
		}

	} else {
		if flags&negotiateFlagNTLMSSPNEGOTIATESIGN == negotiateFlagNTLMSSPNEGOTIATESIGN {
			NTSSPObj.MIC = NTLMSSP_Auth_Bytes[64:80]
		}
	}

	//TODO add test cases for this
	return NTSSPObj, nil

}

// Get the starting and ending points between two numbers
// Only works when the fields is following the format: fieldLen(2 bytes),fieldLenMan(2 bytes),fieldBufferOffset(4 bytes)
func getByteLocation(fields []byte) (int, int) {
	Len := fields[0:2]
	Offset := fields[4:8]
	StartByte := binary.LittleEndian.Uint16(Offset)
	EndByte := StartByte + (binary.LittleEndian.Uint16(Len))

	return int(StartByte), int(EndByte)
}

// Return a slice of human readable flags
func getHumanNegoFlagNames(flags uint32) []string {
	var flagsHumanReadable []string

	if flags&negotiateFlagNTLMSSPNEGOTIATEUNICODE == negotiateFlagNTLMSSPNEGOTIATEUNICODE {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_UNICODE")
	}
	if flags&negotiateFlagNTLMNEGOTIATEOEM == negotiateFlagNTLMNEGOTIATEOEM {
		flagsHumanReadable = append(flagsHumanReadable, "NTLM_NEGOTIATE_OEM")
	}

	if flags&negotiateFlagNTLMSSPREQUESTTARGET == negotiateFlagNTLMSSPREQUESTTARGET {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_REQUEST_TARGET")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATESIGN == negotiateFlagNTLMSSPNEGOTIATESIGN {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_SIGN")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATESEAL == negotiateFlagNTLMSSPNEGOTIATESEAL {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_SEAL")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATEDATAGRAM == negotiateFlagNTLMSSPNEGOTIATEDATAGRAM {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_DATAGRAM")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATELMKEY == negotiateFlagNTLMSSPNEGOTIATELMKEY {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_LM_KEY")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATENTLM == negotiateFlagNTLMSSPNEGOTIATENTLM {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_NTLM")
	}

	if flags&negotiateFlagANONYMOUS == negotiateFlagANONYMOUS {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_ANONYMOUS")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATEOEMDOMAINSUPPLIED == negotiateFlagNTLMSSPNEGOTIATEOEMDOMAINSUPPLIED {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATEOEMWORKSTATIONSUPPLIED == negotiateFlagNTLMSSPNEGOTIATEOEMWORKSTATIONSUPPLIED {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATEALWAYSSIGN == negotiateFlagNTLMSSPNEGOTIATEALWAYSSIGN {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_ALWAYS_SIGN")
	}

	if flags&negotiateFlagNTLMSSPTARGETTYPEDOMAIN == negotiateFlagNTLMSSPTARGETTYPEDOMAIN {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_TARGET_TYPE_DOMAIN")
	}

	if flags&negotiateFlagNTLMSSPTARGETTYPESERVER == negotiateFlagNTLMSSPTARGETTYPESERVER {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_TARGET_TYPE_SERVER")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATEEXTENDEDSESSIONSECURITY == negotiateFlagNTLMSSPNEGOTIATEEXTENDEDSESSIONSECURITY {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATEIDENTIFY == negotiateFlagNTLMSSPNEGOTIATEIDENTIFY {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_IDENTIFY")
	}

	if flags&negotiateFlagNTLMSSPREQUESTNONNTSESSIONKEY == negotiateFlagNTLMSSPREQUESTNONNTSESSIONKEY {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_REQUEST_NON_NT_SESSION_KEY")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATETARGETINFO == negotiateFlagNTLMSSPNEGOTIATETARGETINFO {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_TARGET_INFO")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATEVERSION == negotiateFlagNTLMSSPNEGOTIATEVERSION {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_VERSION")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATE128 == negotiateFlagNTLMSSPNEGOTIATE128 {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_128")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATEKEYEXCH == negotiateFlagNTLMSSPNEGOTIATEKEYEXCH {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_KEY_EXCH")
	}

	if flags&negotiateFlagNTLMSSPNEGOTIATE56 == negotiateFlagNTLMSSPNEGOTIATE56 {
		flagsHumanReadable = append(flagsHumanReadable, "NTLMSSP_NEGOTIATE_56")
	}

	return flagsHumanReadable

}

type VersionStruct struct {
	ProductMajor []byte //1 bytes, offset 0
	ProductMinor []byte //1 bytes, offset 1
	ProductBuild []byte //2 bytes, offset 2
	Reserved     []byte //3 bytes, offset 4
	NTLMVersion  []byte //1 bytes, offset 7 ?
}

// Returns a version string
func (v *VersionStruct) HumanString() string {
	major := binary.LittleEndian.Uint16(v.ProductMajor)
	minor := binary.LittleEndian.Uint16(v.ProductMinor)
	build := binary.LittleEndian.Uint16(v.ProductBuild)

	return fmt.Sprintf("Version %d.%d (Build %d)", major, minor, build)

}

//TODO build a database of windows versions

func getVersion(a []byte) (VersionStruct, error) {
	if len(a) != 8 {
		return VersionStruct{}, fmt.Errorf("byte slice size is not the required size for a version struct\n Expected: 8\nGot: %d", len(a))
	}

	var v VersionStruct
	v.ProductMajor = []byte{a[0]}
	v.ProductMinor = []byte{a[1]}
	v.ProductBuild = a[2:4]
	v.Reserved = a[4:7]
	v.NTLMVersion = []byte{a[8]}

	return v, nil
}

// TODO figure out how to parse AVID
type AVID struct {
}

// Returns a readable version of Target Info.
// 2.2.2.1 AV_PAIR https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/%5bMS-NLMP%5d.pdf
func getHumanNegoTargetInfo() {

}
