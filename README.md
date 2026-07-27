# oscore

Pure-Rust `no_std` implementation of OSCORE (RFC 8613) for securing CoAP messages.

## Features

- AES-CCM-16-64-128 authenticated encryption (RFC 8613 mandatory algorithm)
- HKDF-SHA256 key derivation
- Full replay protection with 32-bit sliding window
- Request/response correlation
- Optional EDHOC (RFC 9528) Suite 0 for key establishment

## Usage

```rust
use oscore::{Context, OscoreSeqNum};

// Create security context from pre-shared master secret
let master_secret = [0u8; 16]; // Your pre-shared key
let sender_id = &[0x01];
let recipient_id = &[0x02];

let mut ctx = Context::new_ephemeral(
    &master_secret,
    None, // Optional master salt
    sender_id,
    recipient_id,
)?;

// Protect a CoAP request
let code = 0x01; // GET
let options = &[];
let payload = b"Hello";
let (ciphertext, oscore_option) = ctx.protect_request(code, options, payload)?;

// Unprotect an incoming request
let (code, options, payload) = ctx.unprotect_request(&oscore_option, &ciphertext)?;
```

## Features

- `std` - Enable standard library support
- `edhoc` - Enable EDHOC Suite 0 (X25519/Ed25519) key establishment
- `defmt` - Enable defmt logging for embedded targets
- `log` - Enable log crate logging

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
