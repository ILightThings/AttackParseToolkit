package encodeutil

import (
	"encoding/binary"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

//https://gist.github.com/sail1972/c7f2da14d0f284f7d76a5afce7daacfc

func EncodeToUTF16(s string) ([]byte, error) {
	finalstring, _, err := transform.Bytes(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder(), []byte(s))
	return finalstring, err
}

//https://gist.github.com/sail1972/c7f2da14d0f284f7d76a5afce7daacfc

func DecodeUTF16leBytes(s []byte) (string, error) {
	bs_UTF8LE, _, err := transform.Bytes(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder(), s)
	return string(bs_UTF8LE), err
}

func BytesToUint16(s []byte) uint16 {
	return binary.LittleEndian.Uint16(s)
}
