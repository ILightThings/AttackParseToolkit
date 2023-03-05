package encodeutil

import (
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

func EncodeToUTF16(s string) ([]byte, error) {
	finalstring, _, err := transform.Bytes(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder(), []byte(s))
	return finalstring, err
}
