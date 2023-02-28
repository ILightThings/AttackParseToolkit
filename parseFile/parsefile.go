package parseFile

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
)

//TODO, Parse NMAP xml for targets

// Parse IPs and CIDRS from file
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

func ParseTargetString(target string) ([]string, error) {
	v := validator.New()

	//CIDR ipv4
	err := v.Var(target, "cidr")
	if err == nil {
		return parseCIDR(target), nil
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

func parseCIDR(cidrString string) []string {
	var cidrIPs []string
	ip, cidr, _ := net.ParseCIDR(cidrString)
	for ip := ip.Mask(cidr.Mask); cidr.Contains(ip); inc(ip) {
		cidrIPs = append(cidrIPs, ip.String())

	}
	return cidrIPs
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// TODO, Finish this
// Get FQDN from URL
func parseURL(url string) string {
	return ""

}
