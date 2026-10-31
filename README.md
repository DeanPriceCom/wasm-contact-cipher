# WASM Contact Cipher (`deanprice.com/wasm-contact-cipher`)

[![Go Reference](https://pkg.go.dev/badge/deanprice.com/wasm-contact-cipher.svg)](https://pkg.go.dev/deanprice.com/wasm-contact-cipher)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23826355.svg)](https://doi.org/10.5281/zenodo.23826355)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**WASM Contact Cipher** (`package contactcipher`) is a zero-dependency, deterministic symmetric XOR keystream engine written in Go for **TinyGo** and standard **WebAssembly (`js/wasm`)** applications. It mitigates automated static email, telephone, and messaging web scrapers by binding pre-obfuscated contact payloads to the active browser hostname at runtime.

Extracted from the production micro-WebAssembly architecture powering **[deanprice.com](https://www.deanprice.com/)**.

---

## Architecture & Algorithm

At build time (`go generate`), contact URIs (`mailto:`, `tel:`, `https://wa.me/`) are XOR-masked into raw byte slices—eliminating plaintext strings from both static HTML markup and the compiled WebAssembly `.rodata` section.

1. **Context Folding (64-bit Knuth MMIX LCG):** Folds a 64-bit build seed together with the normalized target domain (`example.org`), lifecycle event (`"load"`), and per-channel nonce (`"email"`, `"phone_GB"`, etc.) using multiplier `0x5851f42d4c957f2d` and odd increment `0x14057b7ef767814f`.
2. **Avalanche Finalization (`SplitMix64`):** Steps the 64-bit state per byte and passes it through Sebastiano Vigna's bijective `SplitMix64` mixer, extracting the top byte (`mixed >> 56`) combined with positional index masking (`^ byte(i)`).
3. **Symmetric Hydration:** Because XOR keystream application is an involution, `Crypt(Crypt(data, ...), ...) == data`. Inside the browser's WebAssembly sandbox, `window.location.hostname` is normalized and fed into `DecryptPayload` to reconstruct the contact URI in memory.

---

## Threat Model & Scope

| Adversary / Scenario | Mitigated? | Mechanism |
| :--- | :---: | :--- |
| Static HTTP / HTML spiders (`curl`, `wget`, Python/Go scrapers) | **Yes** | No plaintext `mailto:` or `tel:` URIs exist in HTML or static assets (facilitating decoy/honeypot substitution in raw HTML). |
| Regex harvesters scanning `.js` / `.wasm` bundles | **Yes** | Contact strings are stored as keystream-masked byte arrays rather than UTF-8 literals. |
| Unauthorized mirror domains cloning HTML + WASM assets | **Yes** | `window.location.hostname` mismatches the build-time target domain, producing a divergent keystream on unauthorized mirrors. |
| Headless Chromium / Playwright inspecting post-load DOM | **No** | Once hydrated into live DOM `href` attributes for legitimate human navigation, a full browser automation engine can inspect the rendered DOM. |
| Offline reverse-engineering of compiled WASM constants | **No** | **Non-goal:** `contactcipher` is a lightweight anti-scraping obfuscation primitive, **not** a CSPRNG or authenticated cipher. |

---

## Installation

```bash
go get deanprice.com/wasm-contact-cipher@latest
```

Requires **Go 1.24+** (standard library only; zero external dependencies). Fully compatible with **TinyGo** (`-target wasm -opt=z -no-debug -panic=trap`) for sub-50 KB micro-WASM binaries.

---

## Usage

### 1. Build-Time Obfuscation (`go generate` / CLI)

```go
package main

import (
	"fmt"

	contactcipher "deanprice.com/wasm-contact-cipher"
)

func main() {
	const seed uint64 = 0xCAFEBABE12345678
	encoded := contactcipher.EncryptPayload("mailto:hello@example.org", seed, "example.org", "email")
	fmt.Printf("%#v\n", encoded)
}
```

### 2. Client-Side WebAssembly Hydration (`js/wasm` / TinyGo)

See [`examples/wasm/main.go`](examples/wasm/main.go) for a complete `syscall/js` bridge:

```go
//go:build js && wasm

package main

import (
	"syscall/js"

	contactcipher "deanprice.com/wasm-contact-cipher"
)

const seed uint64 = 0xCAFEBABE12345678

var emailBytes = []byte{
	0x4d, 0x29, 0x95, 0x2e, 0x87, 0xc6, 0xde, 0x60,
	0x80, 0xd1, 0x84, 0x3b, 0x40, 0xb0, 0xe2, 0xf6,
	0x3e, 0xf7, 0x7f, 0x8a, 0x84, 0x95, 0x8a, 0x02,
}

func main() {
	host := js.Global().Get("location").Get("hostname").String()
	uri := contactcipher.DecryptPayload(emailBytes, seed, host, "email")
	_ = uri // Hydrate DOM anchor href
}
```

Compile with TinyGo:

```bash
tinygo build -opt=z -no-debug -panic=trap -target wasm -o main.wasm ./examples/wasm
```

---

## Citation

If you reference or use **WASM Contact Cipher** in academic literature or systems engineering, please cite the evergreen Concept DOI (**[10.5281/zenodo.23826355](https://doi.org/10.5281/zenodo.23826355)**) or [`CITATION.cff`](CITATION.cff):

```bibtex
@software{price_wasm_contact_cipher_2026,
  author       = {Price, Dean},
  title        = {{WASM Contact Cipher: Client-Side WebAssembly Keystream Obfuscation Routines}},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.23826355},
  url          = {https://doi.org/10.5281/zenodo.23826355}
}
```

---

## Author & Attribution

* **Author:** [Dean Price](https://www.deanprice.com/) — MSc Computer Science (Distinction), University of Hertfordshire
* **ORCID:** [0009-0001-4937-2409](https://orcid.org/0009-0001-4937-2409)
* **Concept DOI:** [10.5281/zenodo.23826355](https://doi.org/10.5281/zenodo.23826355)
* **Production Reference:** [https://www.deanprice.com/](https://www.deanprice.com/) ([`DeanPriceCom/deanprice.com`](https://github.com/DeanPriceCom/deanprice.com))

## License

Released under the [MIT License](LICENSE) © 2026 [Dean Price](https://www.deanprice.com/).
