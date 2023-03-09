package encodeutil

import (
	"encoding/binary"
	"time"

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

// 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
func FiletimeBytesToTime(filetimeBytes []byte) time.Time {
	// A Windows FILETIME is a 64-bit value representing the number of 100-nanosecond
	// intervals since January 1, 1601 UTC.
	// We can convert this to a time.Time object by adding the number of nanoseconds
	// since January 1, 1601 UTC to the Unix epoch (January 1, 1970 UTC).
	const ticksPerNanosecond = 100
	const ticksBetweenEpochs = 116444736000000000
	filetime := binary.LittleEndian.Uint64(filetimeBytes)
	nanoseconds := int64(filetime-ticksBetweenEpochs) * ticksPerNanosecond
	return time.Unix(0, nanoseconds)
}

//Time Wed 8 March 2023 19:26:33.573 UTC
//Unix 1678303593573000000
//Wind 133227771935730000

//Windx10 13322777193573000000
