package hashing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
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
// user is upper case, domain is concat
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

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b?source=recommendations
type NTLMv2_CLIENT_CHALLENGE struct {
	RespType            []byte `ntlmssp:"hexstring"` // 1 bytes, offset 0
	HiRespType          []byte `ntlmssp:"hexstring"` // 1 bytes, offset 1
	Reserved1           []byte `ntlmssp:"hexstring"` // 2 bytes, offset 2 // Needs to be 00 00
	Reserved2           []byte `ntlmssp:"hexstring"` // 4 bytes, offset 4 // Needs to be 00 00 00 00
	TimeStamp           []byte `ntlmssp:"time"`      // 8 bytes offset 8
	ChallengeFromClient []byte `ntlmssp:"hexstring"` // 8 bytes offset 16
	Reserved3           []byte `ntlmssp:"hexstring"` // 4 bytes offset 24 // Needs to be 00 00 00 00
	AvPairs             []byte `ntlmssp:"hexstring"` // Variable bytes, offset 28
}

func (a *NTLMv2_CLIENT_CHALLENGE) Readable() {
	PrintNTLMSSPStruc(*a)
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d43e2224-6fc3-449d-9f37-b90b55a29c80
type NTLMv2_Responce struct {
	Responce  []byte `ntlmssp:"hexstring"` // 16 bytes, offset 0  // Result of GenerateNTLMv2ChallengeProof
	Challenge []byte `ntlmssp:"hexstring"` // Variable, offset 16 // Direct copy from NTLMv2_CLIENT_CHALLENGE
}

func (a *NTLMv2_Responce) Readable() {
	PrintNTLMSSPStruc(*a)
}

// Rename these to follow the offical whitepaper name
type NTLMSSP_Challenge struct {
	Signature       []byte `ntlmssp:"identifyer"`     // 8 bytes offset 0
	MessageType     []byte `ntlmssp:"MessageType"`    // 4 bytes, offset 8
	TargetName      []byte `ntlmssp:"utf16lestring"`  // 8 bytes, offset 12
	NegotiateFlags  []byte `ntlmssp:"NegotiateFlags"` // 4 bytes, offset 20
	ServerChallenge []byte `ntlmssp:"hexstring"`      // 8 bytes, offset 24
	Reserved        []byte `ntlmssp:"hexstring"`      // 8 bytes, offset 32
	TargetInfo      []byte `ntlmssp:"AV_Pair"`        // 8 bytes, offset 40 //AVID
	Version         []byte `ntlmssp:"version"`        // 8 bytes, offset 48
}

// Prints a human readble verson of the NTLMSSP_Challenge to the console
func (a *NTLMSSP_Challenge) Readable() {
	PrintNTLMSSPStruc(*a)
}

// Parses the NTLMSSP_Challenge to a NTLMSSP_Challenge struct
func ParseNTLMSSP_Challenge(NTLMSSP_Challenge_Bytes []byte) (NTLMSSP_Challenge, error) {
	var NTSSPObj NTLMSSP_Challenge

	NTLMSSP_Identifyer := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}
	if !bytes.Equal(NTLMSSP_Challenge_Bytes[0:8], NTLMSSP_Identifyer) {
		return NTSSPObj, errors.New("NTLMSSP Header is not correct")

	}

	NTSSPObj.MessageType = NTLMSSP_Challenge_Bytes[8:12]

	//TODO, each of these headers should be a property of the NTLMSSPObj
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
	NTSSPObj.NegotiateFlags = NTLMSSP_Challenge_Bytes[20:24]

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
	Signature                 []byte `ntlmssp:"identifyer"`     // 8 bytes, offset 0
	MessageType               []byte `ntlmssp:"MessageType"`    // 4 bytes, offset 8
	LmChallengeResponse       []byte `ntlmssp:"hexstring"`      // 8 bytes, offset 12
	NtChallengeResponse       []byte `ntlmssp:"hexstring"`      // 8 bytes, offset 20
	DomainName                []byte `ntlmssp:"utf16lestring"`  // 8 bytes, offset 28
	UserName                  []byte `ntlmssp:"utf16lestring"`  // 8 bytes, offset 36
	Workstation               []byte `ntlmssp:"utf16lestring"`  // 8 bytes, offset 44
	EncryptedRandomSessionKey []byte `ntlmssp:"hexstring"`      // 8 bytes, offset 52
	NegotiateFlags            []byte `ntlmssp:"NegotiateFlags"` // 4 bytes, offset 60
	Version                   []byte `ntlmssp:"version"`        // 8 bytes, Variable Offset //that SHOULD be populated only when the NTLMSSP_NEGOTIATE_VERSION flag is set in the NegotiateFlags field
	MIC                       []byte `ntlmssp:"hexstring"`      // 8 bytes, Variable Offset
}

func (a *NTLMSSP_Auth) Readable() {
	PrintNTLMSSPStruc(*a)

}

func ParseNTLMSSP_Auth(NTLMSSP_Auth_Bytes []byte) (NTLMSSP_Auth, error) {

	var NTSSPObj NTLMSSP_Auth

	NTLMSSP_Identifyer := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}
	if !bytes.Equal(NTLMSSP_Auth_Bytes[0:8], NTLMSSP_Identifyer) {
		return NTSSPObj, errors.New("NTLMSSP Header is not correct")
	}

	NTSSPObj.MessageType = NTLMSSP_Auth_Bytes[8:12]

	LanResponceFields := NTLMSSP_Auth_Bytes[12:20]
	lmStart, lmEnd := getByteLocation(LanResponceFields)
	NTSSPObj.LmChallengeResponse = NTLMSSP_Auth_Bytes[lmStart:lmEnd]

	NtChallengeResponseFields := NTLMSSP_Auth_Bytes[20:28]
	NtChallStart, NtChallEnd := getByteLocation(NtChallengeResponseFields)
	NTSSPObj.NtChallengeResponse = NTLMSSP_Auth_Bytes[NtChallStart:NtChallEnd]

	DomainNameFields := NTLMSSP_Auth_Bytes[28:36]
	DomainNameStart, DomainNameEnd := getByteLocation(DomainNameFields)
	NTSSPObj.DomainName = NTLMSSP_Auth_Bytes[DomainNameStart:DomainNameEnd]

	UserNameFields := NTLMSSP_Auth_Bytes[36:44]
	UserNameStart, UsernameEnd := getByteLocation(UserNameFields)
	NTSSPObj.UserName = NTLMSSP_Auth_Bytes[UserNameStart:UsernameEnd]

	WorkstationFields := NTLMSSP_Auth_Bytes[44:52]
	WorkstationStart, WorkStationEnd := getByteLocation(WorkstationFields)
	NTSSPObj.Workstation = NTLMSSP_Auth_Bytes[WorkstationStart:WorkStationEnd]

	EncryptedRandomSessionKeyFields := NTLMSSP_Auth_Bytes[52:60]
	SessionKeyStart, SessionKeyEnd := getByteLocation(EncryptedRandomSessionKeyFields)
	NTSSPObj.EncryptedRandomSessionKey = NTLMSSP_Auth_Bytes[SessionKeyStart:SessionKeyEnd]

	NTSSPObj.NegotiateFlags = NTLMSSP_Auth_Bytes[60:64]

	flags := binary.LittleEndian.Uint32(NTSSPObj.NegotiateFlags)

	// MIC and Version fields are dependant on the Flags that require them.

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

	return NTSSPObj, nil

}

// Get the starting and ending points between two numbers
// Only works when the fields is following the format: fieldLen(2 bytes),fieldLenMax(2 bytes),fieldBufferOffset(4 bytes)
func getByteLocation(fields []byte) (int, int) {
	Len := fields[0:2]
	Offset := fields[4:8]
	StartByte := binary.LittleEndian.Uint16(Offset)
	EndByte := StartByte + (binary.LittleEndian.Uint16(Len))

	return int(StartByte), int(EndByte)
}

// TODO move this to the PrintNTLMSSPStruc
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
	ProductMajor byte   //1 bytes, offset 0
	ProductMinor byte   //1 bytes, offset 1
	ProductBuild []byte //2 bytes, offset 2
	Reserved     []byte //3 bytes, offset 4
	NTLMVersion  byte   //1 bytes, offset 7 ?
}

// Move this to the PrintNTLMSSPStruc
// Returns a version string
func (v *VersionStruct) HumanString() string {
	major := v.ProductMajor
	minor := v.ProductMinor
	build := binary.LittleEndian.Uint16(v.ProductBuild)

	return fmt.Sprintf("Version %d.%d (Build %d)", major, minor, build)

}

//TODO build a database of windows versions

func getVersion(a []byte) (VersionStruct, error) {
	if len(a) != 8 {
		return VersionStruct{}, fmt.Errorf("byte slice size is not the required size for a version struct\n Expected: 8\nGot: %d", len(a))
	}

	var v VersionStruct
	v.ProductMajor = a[0]
	v.ProductMinor = a[1]
	v.ProductBuild = a[2:4]
	v.Reserved = a[4:7]
	v.NTLMVersion = a[7]

	return v, nil
}

func PrintNTLMSSPStruc(a interface{}) {
	t := reflect.TypeOf(a)
	v := reflect.ValueOf(a)
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("ntlmssp")
		data := v.Field(i)
		field := t.Field(i).Name

		switch tag {
		case "utf16lestring":
			//I have to learn more about this nonsense
			decode, err := encodeutil.DecodeUTF16leBytes(data.Interface().([]byte))
			if err != nil {
				fmt.Printf("%s: Error Decoding: %s\n", field, err.Error())
			} else {
				fmt.Printf("%s: %s\n", field, decode)
			}
		case "hexstring":
			decode := data.Interface().([]byte)
			fmt.Printf("%s: %x\n", field, decode)
		case "version":
			version, err := getVersion(data.Interface().([]byte))
			if err != nil {
				fmt.Printf("%s: Error Getting Version. %v \n", field, err)
			} else {
				fmt.Printf("%s: %s\n", field, version.HumanString())
			}
		case "time":
			timedecode := encodeutil.FiletimeBytesToTime(data.Interface().([]byte))
			fmt.Printf("%s: %s\n", field, timedecode.Local())

		case "MessageType":
			mtype := binary.LittleEndian.Uint32(data.Interface().([]byte))
			var mtypename string
			switch mtype {
			case NEGOTIATE_MESSAGE:
				mtypename = "NEGOTIATE_MESSAGE (0x1)"
			case CHALLENGE_MESSAGE:
				mtypename = "CHALLENGE_MESSAGE (0x2)"
			case AUTHENTICATE_MESSAGE:
				mtypename = "AUTHENTICATE_MESSAGE (0x3)"
			default:
				mtypename = fmt.Sprintf("UNKNOWN MESSAGE TYPE (%d)", mtype)
			}
			fmt.Printf("%s: %s\n", field, mtypename)

		default:
			fmt.Printf("%s: Not Yet Implemented\n", field)

		}

		//fmt.Printf("%v: %v - %v\n", , tag)
	}
}

type AVID struct {
	MsvAvEOL             []byte `ntlmssp:"void"`          // 0x0000 Signify end of AVID
	MsvAvNbComputerName  []byte `ntlmssp:"utf16lestring"` // 0x0001
	MsvAvNbDomainName    []byte `ntlmssp:"utf16lestring"` // 0x0002
	MsvAvDnsComputerName []byte `ntlmssp:"utf16lestring"` // 0x0003
	MsvAvDnsDomainName   []byte `ntlmssp:"utf16lestring"` // 0x0004
	MsvAvDnsTreeName     []byte `ntlmssp:"utf16lestring"` // 0x0005
	MsvAvFlags           []byte `ntlmssp:"avFlags"`       // 0x0006
	MsvAvTimestamp       []byte `ntlmssp:"time"`          // 0x0007
	MsvAvSingleHost      []byte `ntlmssp:"tbd"`           // 0x0008
	MsvAvTargetName      []byte `ntlmssp:"utf16lestring"` // 0x0009 CIFS/Targetname
	MsvAvChannelBindings []byte `ntlmssp:"tbd"`           // 0x000A

}

func (a *AVID) Readable() {
	PrintNTLMSSPStruc(*a)
}

// Returns a AVID obj Target Info.
// 2.2.2.1 AV_PAIR https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/%5bMS-NLMP%5d.pdf
func getAVIDObj(avidbytes []byte) (AVID, error) {
	var AVobj AVID
	counter := uint16(0)

	for {
		var AVtype uint16
		var AVlen uint16
		var AVsubject []byte

		//Break statement if MsvAvEOL
		AVtype = encodeutil.BytesToUint16(avidbytes[counter : counter+2])
		if AVtype == 0 {
			break
		}
		AVlen = encodeutil.BytesToUint16(avidbytes[counter+2 : counter+4])
		AVsubject = (avidbytes[counter+4 : counter+4+AVlen])
		switch AVtype {
		case 1:
			AVobj.MsvAvNbComputerName = AVsubject
		case 2:
			AVobj.MsvAvNbDomainName = AVsubject
		case 3:
			AVobj.MsvAvDnsComputerName = AVsubject
		case 4:
			AVobj.MsvAvDnsDomainName = AVsubject
		case 5:
			AVobj.MsvAvDnsTreeName = AVsubject
		case 6:
			AVobj.MsvAvFlags = AVsubject
		case 7:
			AVobj.MsvAvTimestamp = AVsubject
		case 8:
			AVobj.MsvAvSingleHost = AVsubject
		case 9:
			AVobj.MsvAvTargetName = AVsubject
		case 10:
			AVobj.MsvAvChannelBindings = AVsubject

		}
		counter += 4 + AVlen

	}

	return AVobj, nil

}
