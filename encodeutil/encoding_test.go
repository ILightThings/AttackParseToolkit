package encodeutil

import (
	"bytes"
	"testing"
	"time"
)

func TestEncodeToUTF16(t *testing.T) {
	outputbytes, err := EncodeToUTF16("password")
	if err != nil {
		t.Fatal(err)
	}
	expectedBytes := []byte{0x70, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x64, 0x00}

	if !bytes.Equal(expectedBytes, outputbytes) {
		t.Errorf("bytes do not much.\nExpected:\n%+v\nGot:\n%+v", expectedBytes, outputbytes)
	}
}

func TestWindowsFiletimeToTime(t *testing.T) {
	testcase := []byte{0x0b, 0xd7, 0xd7, 0x87, 0x85, 0x27, 0xd2, 0x01}
	longForm := "Jan 2, 2006 03:04:05.000000000 (MST)"
	expectTime, err := time.Parse(longForm, "Oct 16, 2016 04:16:01.036877900 (EDT)")
	if err != nil {
		t.Fatal(err)
	}

	resultTime := FiletimeBytesToTime(testcase)
	if resultTime != expectTime {
		t.Errorf("Time does not match.\nExpected:\n%d\nGot:\n%d", expectTime.UnixNano(), resultTime.UnixNano())
	}
}
