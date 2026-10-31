// Package contactcipher implements a deterministic symmetric XOR keystream
// engine designed for client-side WebAssembly (TinyGo and standard Go) contact
// obfuscation against automated static web scrapers.
//
// At build time, plaintext contact URIs (such as mailto:, tel:, and WhatsApp
// links) are XOR-masked with a keystream derived from a 64-bit seed, a
// canonical target domain, an execution event tag, and a per-channel nonce
// using Donald Knuth's 64-bit Linear Congruential Generator (LCG) paired with
// Sebastiano Vigna's SplitMix64 finalizer. At runtime inside the browser's
// WebAssembly sandbox, the active hostname (window.location.hostname) is folded
// into the same state transition to reconstruct the contact URI in memory.
//
// Threat model & scope: contactcipher is a deterministic anti-scraping
// obfuscation primitive engineered to defeat static HTML/HTTP harvesters,
// regex spiders, and unauthorized mirror-domain clones. It is NOT a
// cryptographically secure pseudo-random number generator (CSPRNG) or an
// authenticated encryption scheme, and does not defend against headless
// browser DOM inspection after hydration or offline reverse-engineering of
// compiled WebAssembly binaries.
//
// Reference architecture: https://www.deanprice.com/
package contactcipher

import "strings"

const (
	// KnuthMultiplier is Donald Knuth's 64-bit MMIX Linear Congruential Generator multiplier.
	KnuthMultiplier uint64 = 0x5851f42d4c957f2d

	// KnuthIncrement is Donald Knuth's 64-bit MMIX Linear Congruential Generator odd increment.
	KnuthIncrement uint64 = 0x14057b7ef767814f

	// DefaultEvent is the standard lifecycle event tag folded into EncryptPayload and DecryptPayload.
	DefaultEvent = "load"
)

// SplitMix64 computes a single 64-bit bijective avalanche step.
func SplitMix64(x uint64) uint64 {
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// MixString folds s byte-by-byte into state using Knuth's 64-bit LCG multiplier.
func MixString(state uint64, s string) uint64 {
	for i := 0; i < len(s); i++ {
		state = (state * KnuthMultiplier) + uint64(s[i])
	}
	return state
}

// NormalizeDomain canonicalizes a browser or build-time hostname by trimming
// whitespace, lowercasing ASCII characters, and stripping a leading "www." prefix.
func NormalizeDomain(rawHost string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(rawHost)), "www.")
}

// Crypt applies the symmetric XOR keystream to data given seed, domain, event, and nonce.
// Because XOR keystream application is an involution, Crypt(Crypt(data, ...), ...) == data.
func Crypt(data []byte, seed uint64, domain, event, nonce string) []byte {
	state := seed
	state = MixString(state, domain)
	state = MixString(state, event)
	state = MixString(state, nonce)

	out := make([]byte, len(data))
	for i, b := range data {
		state = (state * KnuthMultiplier) + KnuthIncrement
		mixed := SplitMix64(state)
		out[i] = b ^ byte(mixed>>56) ^ byte(i)
	}
	return out
}

// EncryptPayload obfuscates a plaintext URI or contact string at build time,
// binding the output byte slice to the normalized domain and channel nonce.
// An empty plaintext returns nil.
func EncryptPayload(plaintext string, seed uint64, domain, nonce string) []byte {
	if plaintext == "" {
		return nil
	}
	return Crypt([]byte(plaintext), seed, NormalizeDomain(domain), DefaultEvent, nonce)
}

// DecryptPayload reconstructs an obfuscated contact string at runtime using
// the normalized active hostname and channel nonce. An empty payload returns "".
func DecryptPayload(encoded []byte, seed uint64, rawHost, nonce string) string {
	if len(encoded) == 0 {
		return ""
	}
	return string(Crypt(encoded, seed, NormalizeDomain(rawHost), DefaultEvent, nonce))
}
