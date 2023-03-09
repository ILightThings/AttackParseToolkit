package parse

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
)

//TODO, Parse NMAP xml for targets

// Parse targets divieded by new line from the specificed file and returns a slice of network targets (IP/FQDN).
func ParseTagetsFromFile(filepath string) ([]string, error) {

	//Open File
	readfile, err := os.Open(filepath)
	if err != nil {
		return []string{}, err
	}

	//Serperate file by lines
	fileScanner := bufio.NewScanner(readfile)
	fileScanner.Split(bufio.ScanLines)

	var lines []string
	for fileScanner.Scan() {
		data := strings.TrimSpace(fileScanner.Text())
		if data == "" {
			continue
		}

		lines = append(lines, data)
	}

	//Target Parsing
	var proccessedTarget []string
	for _, entry := range lines {
		parseEntry, err := ParseTargetString(entry)
		if err != nil {
			//log.Print(err)
			continue
		}
		proccessedTarget = append(proccessedTarget, parseEntry...)
	}
	return proccessedTarget, nil

}

// ParseTargetString will parse the target string and extract a slice of FQDN/IPs that can be used in a network attacks.
// Currently support CIDRv4, IP address, URL, FQDN.
func ParseTargetString(target string) ([]string, error) {
	v := validator.New()

	//CIDR ipv4
	err := v.Var(target, "cidr")
	if err == nil {
		CIDR_Targets, err := ParseCIDR(target)
		return CIDR_Targets, err
	}

	//IPv4 or IPv6 Address
	err = v.Var(target, "ip")
	if err == nil {
		return []string{target}, nil
	}

	//URL
	err = v.Var(target, "url")
	if err == nil {
		return []string{parseURL(target)}, nil
	}

	//FQDN
	err = v.Var(target, "fqdn")
	if err == nil {
		return []string{target}, nil
	}

	//No match
	return []string{}, fmt.Errorf("no matching pattern for target: %s", target)

}

// Parse a CIDR notation and returns a slice of IP address with in that CIDR
func ParseCIDR(cidrString string) ([]string, error) {
	var cidrIPs []string
	ip, cidr, err := net.ParseCIDR(cidrString)
	if err != nil {
		return []string{}, err
	}
	for ip := ip.Mask(cidr.Mask); cidr.Contains(ip); inc(ip) {
		cidrIPs = append(cidrIPs, ip.String())

	}
	return cidrIPs, nil
}

// increase IP by 1
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Get FQDN from URL
func parseURL(targeturl string) string {
	hostname, _ := url.Parse(targeturl)
	return hostname.Hostname()

}
