package main

import "C"

import (
	"crypto/sha1"
)

//export NativePassword
func NativePassword(password *C.char, salt *C.char) (*C.char) {

	sha1 := sha1.New()
	sha1.Write([]byte(C.GoString(password)))
	passwordSHA1 := sha1.Sum(nil)

	sha1.Reset()
	sha1.Write(passwordSHA1)
	hash := sha1.Sum(nil)

	sha1.Reset()
	sha1.Write([]byte(C.GoString(salt)))
	sha1.Write(hash)
	randomSHA1 := sha1.Sum(nil)

	// nativePassword = passwordSHA1 ^ randomSHA1
	nativePassword := make([]byte, len(randomSHA1))
	for i := range randomSHA1 {
		nativePassword[i] = passwordSHA1[i] ^ randomSHA1[i]
	}

	return C.CString(string(nativePassword))
}

func main() {}
