# Secure Remote Password (SRP 6 / 6a)

[![crates.io](https://img.shields.io/crates/v/srp6.svg)](https://crates.io/crates/srp6)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![codecov](https://codecov.io/gh/sassman/srp6-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/sassman/srp6-rs)

> A safe implementation of the secure remote password authentication and key-exchange protocol (SRP version 6a). Version 6 (legacy) is as features available.

## About SRP

> The Secure Remote Password protocol performs secure remote authentication of short human-memorizable passwords and resists both passive and active network attacks. Because SRP offers this unique combination of password security, user convenience, and freedom from restrictive licenses, it is the most widely standardized protocol of its type, and as a result is being used by organizations both large and small, commercial and open-source, to secure nearly every type of human-authenticated network traffic on a variety of computing platforms.

read more at [srp.stanford.edu](http://srp.stanford.edu) and in [RFC2945] that describes in detail the Secure remote password protocol.

## Features

- client and server implementation of SRP 6 / 6a as in [RFC2945]
- key length of 256 to 4096 bit provided as in [RFC5054]
- free of unsafe code
- no openssl dependencies
- rust native

## Documentation

To avoid code duplications this README is kept lean, please find examples and code at:

- [official crate docs](https://docs.rs/srp6)
- [examples of usage](https://github.com/sassman/srp6-rs/blob/main/examples)

[RFC2945]: https://datatracker.ietf.org/doc/html/rfc2945
[RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054#appendix-A

## License

- **[MIT License](LICENSE)**
- Copyright 2021 © [Sven Assmann](https://www.d34dl0ck.me)
