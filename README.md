# Socks-Http-Kit

[![Build Status](https://github.com/Brainmaker/Obfswire/actions/workflows/ci.yml/badge.svg)](https://github.com/Brainmaker/Obfswire/actions/workflows/ci.yml)
![docs.rs](https://img.shields.io/docsrs/obfswire)
[![codecov](https://codecov.io/github/Brainmaker/Obfswire/graph/badge.svg?token=WVLFE0TA33)](https://codecov.io/github/Brainmaker/Obfswire)
![License: MIT or Apache 2.0](https://img.shields.io/badge/license-MIT%20or%20Apache%202.0-blue)

[API Documentation](https://docs.rs/obfswire/latest/obfswire/)

A lightweight library for SOCKS5 and HTTP proxy protocol encoding and parsing,
designed to facilitate complex proxy applications.

This library serves as a foundation layer for higher-level proxy protocols.
It provides a set of Tokio-based asynchronous functions specifically for
parsing and processing SOCKS5 and HTTP proxy protocol requests and responses.
The library employs an I/O-agnostic design, meaning it doesn't spawn internal
threads, establish network connections, or perform DNS resolution.
Instead, it delegates these controls entirely to the user code,
enabling flexible integration with various proxy applications.

Socks-Http-Kit supports:

- SOCKS5 client and server implementations.
    - Support for CONNECT, BIND, and UDP_ASSOCIATE commands.
    - Username/password authentication mechanism.

- HTTP proxy client and server implementations.
    - HTTP BASIC authentication support.

## License

This project is licensed under either of
- MIT license ([LICENSE-MIT](http://opensource.org/licenses/MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](http://www.apache.org/licenses/LICENSE-2.0)) at your option.
