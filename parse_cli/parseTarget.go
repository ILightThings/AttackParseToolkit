package parse_cli

import (
	"os"

	"github.com/ILightThings/AttackParseToolkit/parseFile"
)

//Similar to crackmapexecs target parameter

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
