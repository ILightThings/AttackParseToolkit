package encodeutil

import (
	"bytes"
	"testing"
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
