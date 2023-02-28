package parse_cli

import (
	"fmt"
	"os"
	"regexp"

	"github.com/ILightThings/AttackParseToolkit/parseFile"
)

type ImpacketAuth struct {
	Username string
	Password string
	Domain   string
	Target   string
}

// DOMAIN USER PASSWORD TARGET
const IMPACKET_TARGET_RE = "(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)"

// DOMAIN USER PASSWORD
const IMPACKET_USER_RE = "(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?"

// TODO make unit test for this.
// Similar to crackmapexecs target parameter
func ParseParameterStringTarget(target string) ([]string, error) {
	//If file exist

	//TODO switch this with open file as we will need it anyway
	_, err := os.Stat(target)
	if err == nil {
		targetsFromFile, err1 := parseFile.ParseTagetsFromFile(target)
		return targetsFromFile, err1

	} else {
		stringTarget, err1 := parseFile.ParseTargetString(target)
		return stringTarget, err1
	}

}

func ParseParameterCredentialImpacket(userstring string) (ImpacketAuth, error) {
	var impacket_cred_obj ImpacketAuth
	val, err := regexp.MatchString(IMPACKET_USER_RE, userstring)
	if !val {
		return impacket_cred_obj, fmt.Errorf("%s is not a valid impacket string", userstring)
	}

	if err != nil {
		return impacket_cred_obj, fmt.Errorf("invalid impacket regex pattern %s", IMPACKET_USER_RE)
	}

	r := regexp.MustCompile(IMPACKET_USER_RE)
	results := r.FindStringSubmatch(userstring)
	impacket_cred_obj.Domain = results[1]
	impacket_cred_obj.Username = results[2]
	impacket_cred_obj.Password = results[3]

	return impacket_cred_obj, nil

}

//https://github.com/fortra/impacket/blob/8799a1a2c42ad74423841d21ed5f4193ea54f3d5/impacket/examples/utils.py

/*
   if hasattr(args, 'target') and args.target:
       for target in args.target:
           if os.path.exists(target):
               target_file_type = identify_target_file(target)
               if target_file_type == 'nmap':
                   targets.extend(parse_nmap_xml(target, args.protocol))
               elif target_file_type == 'nessus':
                   targets.extend(parse_nessus_file(target, args.protocol))
               else:
                   with open(target, 'r') as target_file:
                       for target_entry in target_file:
                           targets.extend(parse_targets(target_entry.strip()))
           else:
               targets.extend(parse_targets(target))

*/

//TODO add domain/user:password@target parse like in impacket
