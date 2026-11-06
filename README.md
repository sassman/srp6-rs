# Secure Remote Password (SRP 6 / 6a)

[![crates.io](https://img.shields.io/crates/v/srp6.svg)](https://crates.io/crates/srp6)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![codecov](https://codecov.io/gh/sassman/srp6-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/sassman/srp6-rs)

> A safe implementation of the secure remote password authentication and key-exchange protocol (SRP version 6a).

## About SRP6

> The Secure Remote Password protocol performs secure remote authentication of short human-memorizable passwords and resists both passive and active network attacks. Because SRP offers this unique combination of password security, user convenience, and freedom from restrictive licenses, it is the most widely standardized protocol of its type, and as a result is being used by organizations both large and small, commercial and open-source, to secure nearly every type of human-authenticated network traffic on a variety of computing platforms.

read more at [srp.stanford.edu](http://srp.stanford.edu) and in [RFC2945] that describes in detail the Secure remote password protocol.

## Features

- client and server implementation of SRP 6 / 6a as in [RFC2945]
- key length of 1024 to 8192 bit provided as in [RFC5054]
- sha512 hashing instead of sha1
- free of unsafe code
- no openssl dependencies
- rust native

## Feature flags

- `default` - uses `hash-sha512` and keys >= 2048 bit
- `hash-sha1` - swaps the hash function to SHA-1, which is weak; the RFC 5054 groups are still available, so this alone does not shrink your keys.
- `wow-1-12-1` - the World of Warcraft 1.12.1 (build 5875) flavour: `hash-sha1`, `k = 3`, uppercased username and password, and that client's 256-bit group (`srp6::wow`). **Warning: do not use this for modern, production-grade applications.** Its cryptographic parameters are far below current practice: SHA-1 as the hash, and a 256-bit modulus where this crate asks for >= 2048 bit in production. It exists to talk to a client that shipped in 2006, and later clients changed the flavour.

Those flags are only used for specific test scenarios and should not be used in production code.
- `test-rfc-5054-appendix-b`

## Documentation

To avoid code duplications this README is kept lean, please find examples and code at:

- [official crate docs](https://docs.rs/srp6)
- [formulas and protocol details](https://docs.rs/srp6/latest/srp6/protocol_details/index.html)
- [usage examples](https://github.com/sassman/srp6-rs/blob/main/examples)

[RFC2945]: https://datatracker.ietf.org/doc/html/rfc2945
[RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054#appendix-A

## License

- **[MIT License](LICENSE)**
- Copyright 2021 - 2025 © [Sven Kanoldt](https://www.d34dl0ck.me)
