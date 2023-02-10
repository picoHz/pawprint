# Pawprint

🐾 A simple web app for inspecting TLS fingerprints.

## Demo

Visit https://pawprint.dev/

## Installation

```bash
cargo install pawprint
```

## Starting the server

```bash
pawprint 0.0.0.0:443 --certs path/to/certs.pem --key path/to/key.pem
```

## Development

```bash
# Generate a self-signed certificate
cargo install rcgen
rcgen

cargo r -- 127.0.0.1:8443 --certs certs/cert.pem --key certs/key.pem
```

## Credit

This program is inspired by the following sites / libraries.

- [TLS fingerprinting: How it works, where it is used and how to control your signature](https://lwthiker.com/networks/2022/06/17/tls-fingerprinting.html)

- [TLSFingerprint.io](https://tlsfingerprint.io/)

- [salesforce/ja3](https://github.com/salesforce/ja3)

- [ja3-rustls](https://crates.io/crates/ja3-rustls)

## License

This software is licensed under the AGPLv3.