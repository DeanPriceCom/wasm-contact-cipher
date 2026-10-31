# Security Policy

## Scope & Threat Model

`deanprice.com/wasm-contact-cipher` (`package contactcipher`) is a deterministic anti-scraping obfuscation primitive engineered to defeat static HTML/HTTP harvesters, regex spiders, and unauthorized mirror-domain clones.

It is **not** a cryptographically secure pseudo-random number generator (CSPRNG) or an authenticated encryption scheme, and does not claim confidentiality against:
- Headless browser DOM inspection after client-side hydration.
- Offline reverse-engineering of compiled WebAssembly binaries containing embedded seeds and byte slices.

## Reporting a Vulnerability

Please **do not** report security defects or implementation bugs via public disclosures.

1. **GitHub Private Vulnerability Reporting (Preferred):** Submit a confidential advisory directly through this repository's [Security Advisories tab](https://github.com/DeanPriceCom/wasm-contact-cipher/security/advisories/new).
2. **Author Contact Channels:** Verified contact channels for Dean Price are available via standard web browsers at [https://www.deanprice.com/](https://www.deanprice.com/).
