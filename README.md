# Rust-TestSSL

A Rust implementation of the popular [testssl.sh](https://github.com/drwetter/testssl.sh) tool for testing TLS/SSL security and configuration.

## Project Structure

```
src/
├── errors.rs              # Error handling
├── lib.rs                 # Library entry
├── main.rs                # Main program entry
├── output.rs              # Output formatting
├── rating.rs              # Rating system
├── scanner/               # Core scanning functionality
│   ├── network/          # Network-related scanning
│   │   ├── dns_scanner.rs
│   │   ├── http_scanner.rs
│   │   ├── mod.rs
│   │   └── tls_scanner.rs
│   ├── security/         # Security-related scanning
│   │   ├── mod.rs
│   │   └── vulnerability_scanner.rs
│   ├── simulation/       # Client simulation
│   │   ├── mod.rs
│   │   └── client_simulation.rs
│   ├── tls/             # TLS-related scanning
│   │   ├── forward_secrecy_scanner.rs
│   │   ├── mod.rs
│   │   └── server_defaults_scanner.rs
│   └── mod.rs
```

## Core Components

### Network Scanning (scanner/network/)
- **DNS Scanner**: Domain resolution and DNS record checks
- **HTTP Scanner**: HTTP security headers inspection
- **TLS Scanner**: TLS protocol versions and configuration checks

### Security Scanning (scanner/security/)
- **Vulnerability Scanner**: Detection of common SSL/TLS vulnerabilities
  - Heartbleed
  - CCS Injection
  - ROBOT
  - BEAST
  - POODLE
  - And more...

### TLS Scanning (scanner/tls/)
- **Forward Secrecy Scanner**: Tests for forward secrecy support
  - Cipher suite analysis
  - Key exchange algorithms
  - Signature algorithms
  - Elliptic curves support

- **Server Defaults Scanner**: Checks server configuration
  - TLS extensions
  - Session resumption
  - Certificate details
  - OCSP stapling
  - Certificate transparency

### Client Simulation (scanner/simulation/)
- Simulates various client behaviors
- Tests compatibility with different browsers and platforms
- Checks protocol and cipher suite negotiations

## Supporting Modules

### certificates/
- Certificate chain validation
- Certificate information extraction
- OCSP status checking
- CT log verification

### ciphers/
- Cipher suite detection
- Priority analysis
- Key exchange algorithm testing

### protocols/
- TLS/SSL version support detection
- Protocol downgrade protection
- Protocol extension analysis

### rating/
- Security scoring system
- Configuration assessment
- Best practices evaluation

## Development Status

- [x] Basic framework
- [x] TLS connection establishment
- [x] Certificate analysis
- [x] Client simulation
- [x] DNS scanning
- [x] HTTP security headers
- [ ] Complete vulnerability scanning
- [ ] Comprehensive testing

## Contributing

1. Follow Rust coding standards
2. Add necessary test cases
3. Update relevant documentation
4. Test locally before submitting PR

## License

MIT