package broadlink

import (
	// "fmt"
	// "os"
	"testing"
)

func TestCipher(t *testing.T) {

	var dev Device

	var src = []string{
		"take some string for test source and feed it.",     // 45 bytes
		"Go take some string for test source and feed it.",  // 48 bytes: just fit to aes block
		"Go take some string for test source and feed it..", // 49 bytes
	}

	for _, s := range src {
		encrypted := dev.Encrypt([]byte(s))

		decrypted := dev.Decrypt(encrypted)
		if string(decrypted[:len(s)]) != s {
			t.Fatal("decryption failed")
		}
		for i := len(s); i < len(decrypted); i++ {
			if decrypted[i] != 0 {
				t.Fatal("padding is not zero")
			}
		}
	}
}
