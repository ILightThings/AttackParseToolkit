package hashing

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/md4"
)

// ToNTHash will turn a string into a byte slice representation of a NTLM hash
func ToNTHash(in string) []byte {
	/* Prepare a byte array to return */
	var u16 []byte

	/* Add all bytes, as well as the 0x00 of UTF-16 */
	for _, b := range []byte(in) {
		u16 = append(u16, b)
		u16 = append(u16, 0x00)
	}

	/* Hash the byte array with MD4 */
	mdfour := md4.New()
	mdfour.Write(u16)

	/* Return the output */
	return mdfour.Sum(nil)

}

// ToNTHash will turn a string into a hex string representation of a NTLM hash. Useful for pass the hash attacks
func ToNTHashString(password string) string {
	hash := ToNTHash(password)
	encodedString := hex.EncodeToString(hash)
	return strings.ToUpper(encodedString)
}

func genHMACMD5(key []byte, n []byte) ([]byte, error) {
	hasher := hmac.New(md5.New, key)
	_, err := hasher.Write(n)
	return hasher.Sum(nil), err
}
