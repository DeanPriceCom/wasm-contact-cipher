package contactcipher_test

import (
	"encoding/hex"
	"fmt"

	contactcipher "deanprice.com/wasm-contact-cipher"
)

func ExampleEncryptPayload() {
	const seed uint64 = 0xCAFEBABE12345678
	encoded := contactcipher.EncryptPayload("mailto:hello@example.org", seed, "example.org", "email")
	fmt.Println(hex.EncodeToString(encoded))
	// Output:
	// 4d29952e87c6de6080d1843b40b0e2f63ef77f8a84958a02
}

func ExampleDecryptPayload() {
	const seed uint64 = 0xCAFEBABE12345678
	encoded, _ := hex.DecodeString("4d29952e87c6de6080d1843b40b0e2f63ef77f8a84958a02")
	fmt.Println(contactcipher.DecryptPayload(encoded, seed, "www.example.org", "email"))
	// Output:
	// mailto:hello@example.org
}
