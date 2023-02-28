package parseTarget

import (
	"fmt"
	"os"
)

//Similar to crackmapexecs target parameter

func parseTargetParameter(target string) ([]string, error) {
	//If file exist

	if _, err := os.Stat(target); err == nil {
		fmt.Println("file exist")
	}

	//not file, parse target

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
