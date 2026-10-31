//go:build js && wasm

// Command wasm demonstrates a minimal TinyGo / standard Go WebAssembly DOM
// bridge exposing window.decryptContact(channel) bound to location.hostname.
package main

import (
	"syscall/js"

	contactcipher "deanprice.com/wasm-contact-cipher"
)

const demoSeed uint64 = 0xCAFEBABE12345678

// Pre-obfuscated at build time via:
//
//	contactcipher.EncryptPayload("mailto:hello@example.org", demoSeed, "example.org", "email")
//
// Storing only the pre-computed byte slice keeps raw mailto:/tel: strings out
// of the compiled WebAssembly data section.
var payloads = map[string][]byte{
	"email": {
		0x4d, 0x29, 0x95, 0x2e, 0x87, 0xc6, 0xde, 0x60,
		0x80, 0xd1, 0x84, 0x3b, 0x40, 0xb0, 0xe2, 0xf6,
		0x3e, 0xf7, 0x7f, 0x8a, 0x84, 0x95, 0x8a, 0x02,
	},
}

var (
	runtimeHost string
	keepAlive   []js.Func
)

func decryptContact(_ js.Value, args []js.Value) any {
	channel := "email"
	if len(args) > 0 && !args[0].IsUndefined() && !args[0].IsNull() {
		if ch := args[0].String(); ch != "" {
			channel = ch
		}
	}
	encoded, ok := payloads[channel]
	if !ok {
		return ""
	}
	return contactcipher.DecryptPayload(encoded, demoSeed, runtimeHost, channel)
}

func main() {
	runtimeHost = js.Global().Get("location").Get("hostname").String()

	fn := js.FuncOf(decryptContact)
	keepAlive = append(keepAlive, fn)
	js.Global().Set("decryptContact", fn)

	select {}
}
