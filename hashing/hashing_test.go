package hashing

import "testing"

func TestToNTHash(t *testing.T) {
	test1 := ToNTHashString("password")
	result1 := "8846F7EAEE8FB117AD06BDD830B7586C"

	if test1 != result1 {
		t.Errorf("test1 and result1 do not match.\n%v\n%v", test1, result1)
	}
}
