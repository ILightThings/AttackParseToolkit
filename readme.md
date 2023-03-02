


### Parse File
A function that can be used to parse targets from a file.
Accepeted hosts include:
- IP address 
- CIRD Notation (IPv4 only at the moment)
- FQDN 

#### Example

File1.txt contents:
```
host1.light.local
192.168.10.0/28
10.10.10.10
10.10.20.10
10.20.30.40
lampsforsale.light
```

### ParseParameterCredentialImpacket
A function based off impackets cred parse. Return an ImpacketAuth object.

```go
	cred, err := parse_cli.ParseParameterCredentialImpacket("light.local/ilightthings.local:P@assword")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v", cred)
	//{Username:ilightthings.local Password:P@assword Domain:light.local}
```
Currently does not support a target

### ParseParameterStringTarget


### ToNTHashString
Returns a string version of an NT hash




