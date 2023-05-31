# RC5 Encryption Algorithm implementation in Rust

This crate implements the RC5 algorithm described by Ronald Rivest in this paper: https://www.grc.com/r&d/rc5.pdf

## Building

In the root directory of this project run:

```
$ cargo build
```

## Running tests

In the root directory of this project run:

```
$ cargo test
```

This should run all unit tests and doc tests.

## Usage

The simplest way to use this crate is by invoking `encrypt_default` or `decrypt_default` functions. They will encrypt or decrypt a slice of bytes using RC5/32/12/16 variant of the algorithm, which is the suggested variant by the author.

```rust
use rc5::{encrypt_default, decrypt_default};
let key = [
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
  0x0C, 0x0D, 0x0E, 0x0F,
];

let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

let ct = encrypt_default(key, &pt).unwrap();
let res = decrypt_default(key, &ct).unwrap();

assert_ne!(pt, ct);
assert_eq!(pt, res);
```

If you are going to encrypt or decrypt large amounts of data then its better to use the context object to save time on the key generation step and do it only once upfront for all invocations of encrypt/decrypt. Example:

```rust
let context = rc5::Context::new(key, rounds)?;
let ciphertext = context.encrypt(&plaintext)?;
let plaintext = context.decrypt(&ciphertext)?;
```

The `Context` type can be parametrized as following:
- Word size should be specified as the type parameter W (defaults to `u32`):
```rust
let context = rc5::Context::<u64>::new(key, rounds)?;
```

- The number of rounds is a paramer on the `Context` constructor.
- The key size is the length of the byte vector in `key` parameter in the constructor.


## License
GPL-3