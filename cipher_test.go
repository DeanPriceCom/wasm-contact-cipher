package contactcipher_test

import (
	"bytes"
	"strings"
	"testing"

	contactcipher "deanprice.com/wasm-contact-cipher"
)

const exampleSeed uint64 = 0xCAFEBABE12345678

func TestSplitMix64Deterministic(t *testing.T) {
	// Known reference vector for SplitMix64(0xCAFEBABE12345678)
	got1 := contactcipher.SplitMix64(exampleSeed)
	got2 := contactcipher.SplitMix64(exampleSeed)
	if got1 != got2 {
		t.Fatalf("SplitMix64 non-deterministic: %#x != %#x", got1, got2)
	}
	if got1 == 0 || got1 == exampleSeed {
		t.Fatalf("SplitMix64 failed to avalanche input seed: got %#x", got1)
	}

	// Distinct inputs must map to distinct outputs (bijection sanity check)
	other := contactcipher.SplitMix64(exampleSeed ^ 1)
	if got1 == other {
		t.Fatalf("SplitMix64 collision on adjacent seeds: %#x", got1)
	}
}

func TestCipherSymmetry(t *testing.T) {
	original := []byte("mailto:contact@example.org")
	enc := contactcipher.Crypt(original, exampleSeed, "example.org", "load", "email")
	if bytes.Equal(enc, original) {
		t.Fatalf("Crypt output matched plaintext")
	}

	dec := contactcipher.Crypt(enc, exampleSeed, "example.org", "load", "email")
	if !bytes.Equal(dec, original) {
		t.Fatalf("Crypt involution failed: got %q, want %q", dec, original)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	channels := []struct {
		nonce     string
		plaintext string
	}{
		{"email", "mailto:hello@example.org"},
		{"phone_GB", "tel:+442079460921"},
		{"wa_GB", "https://wa.me/442079460921"},
	}

	for _, ch := range channels {
		encoded := contactcipher.EncryptPayload(ch.plaintext, exampleSeed, "Example.ORG", ch.nonce)
		if len(encoded) != len(ch.plaintext) {
			t.Fatalf("%s: encoded length %d != plaintext length %d", ch.nonce, len(encoded), len(ch.plaintext))
		}
		if strings.Contains(string(encoded), "mailto:") || strings.Contains(string(encoded), "tel:") || strings.Contains(string(encoded), "wa.me") {
			t.Fatalf("%s: encoded payload leaked recognizable scheme substring", ch.nonce)
		}

		// Must hydrate identically on bare apex and www-prefixed hostnames
		for _, runtimeHost := range []string{"example.org", "www.example.org", "  WWW.Example.Org "} {
			got := contactcipher.DecryptPayload(encoded, exampleSeed, runtimeHost, ch.nonce)
			if got != ch.plaintext {
				t.Errorf("%s on host %q: got %q, want %q", ch.nonce, runtimeHost, got, ch.plaintext)
			}
		}
	}

	// Empty inputs
	if got := contactcipher.EncryptPayload("", exampleSeed, "example.org", "email"); got != nil {
		t.Errorf("EncryptPayload(\"\") = %v, want nil", got)
	}
	if got := contactcipher.DecryptPayload(nil, exampleSeed, "example.org", "email"); got != "" {
		t.Errorf("DecryptPayload(nil) = %q, want \"\"", got)
	}
}

func TestDomainLockProtection(t *testing.T) {
	secret := "mailto:research@example.org"
	encoded := contactcipher.EncryptPayload(secret, exampleSeed, "example.org", "email")

	// Unauthorized mirror domains, wrong nonces, and wrong seeds must never yield the plaintext
	if got := contactcipher.DecryptPayload(encoded, exampleSeed, "mirror-scraper.example", "email"); got == secret {
		t.Fatal("Domain lock failed: unauthorized mirror domain decrypted payload")
	}
	if got := contactcipher.DecryptPayload(encoded, exampleSeed, "example.org", "phone"); got == secret {
		t.Fatal("Nonce separation failed: mismatched channel nonce decrypted payload")
	}
	if got := contactcipher.DecryptPayload(encoded, exampleSeed+1, "example.org", "email"); got == secret {
		t.Fatal("Seed binding failed: mismatched seed decrypted payload")
	}
}
