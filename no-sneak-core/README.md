# xlogistx-no-sneak

Placeholder module for future development.

## Status

This module is currently under development and contains no implementation yet.

## Dependencies

- xlogistx-common
- xlogistx-core
- xlogistx-shiro
- xlogistx-opsec

## Package

```
io.xlogistx.nosneak
```

## Building

```bash
mvn clean install -pl no-sneak -am
```

---

# SSL/TLS & PQC Scanner Requirements Document

## Project Overview
A comprehensive SSL/TLS security scanner that replicates SSL Labs functionality plus adds Post-Quantum Cryptography (PQC) scanning capabilities for CNSA 2.0 compliance assessment.

---

## 1. CERTIFICATE ANALYSIS

### 1.1 Certificate Chain Validation
- Verify complete chain from server certificate to root CA
- Check for missing intermediate certificates
- Validate certificate signatures
- Detect self-signed certificates
- Check certificate pinning (HPKP if present)

### 1.2 Certificate Properties
- Subject and Issuer details (CN, O, OU, C)
- Serial number
- Validity period (Not Before / Not After)
- Days until expiration
- Signature algorithm (SHA-256, SHA-384, etc.)
- Key type and size (RSA 2048/4096, ECDSA P-256/P-384)
- Subject Alternative Names (SANs)
- Key Usage and Extended Key Usage
- Basic Constraints
- CRL Distribution Points
- Authority Information Access (AIA)

### 1.3 Certificate Trust
- Trusted by major root stores (Mozilla, Microsoft, Apple, Google)
- Certificate Transparency (CT) log presence
- SCT (Signed Certificate Timestamp) validation
- CAA record compliance
- Revocation status via OCSP
- Revocation status via CRL
- OCSP stapling support and validity

### 1.4 PQC Certificate Requirements
- Detect PQC signature algorithms (ML-DSA/Dilithium)
- Detect hybrid certificates (classical + PQC)
- Validate PQC certificate chains
- Check for NIST-approved PQC signature algorithms
- Identify composite certificate formats
- Report PQC algorithm parameters (security level)

---

## 2. PROTOCOL SUPPORT

### 2.1 Classical Protocol Detection
- SSL 2.0 (flag as critical vulnerability)
- SSL 3.0 (flag as critical vulnerability)
- TLS 1.0 (flag as deprecated)
- TLS 1.1 (flag as deprecated)
- TLS 1.2 (check configuration quality)
- TLS 1.3 (recommended)

### 2.2 Protocol Configuration
- Default protocol version
- Protocol preference order
- Fallback behavior testing
- SCSV fallback support
- Session resumption support (tickets, IDs)
- 0-RTT support (TLS 1.3)
- Early data support and risks

### 2.3 PQC Protocol Requirements
- Detect TLS 1.3 PQC key exchange support
- Identify hybrid key exchange methods
- Check for ML-KEM (Kyber) support
- Check for X25519Kyber768 hybrid
- Check for P256Kyber768 hybrid
- Detect experimental PQC ciphersuites
- Report PQC security levels (1, 3, 5)

---

## 3. CIPHER SUITE ANALYSIS

### 3.1 Cipher Suite Enumeration
- List all supported cipher suites
- Server preference order vs client preference
- Identify cipher suite components:
    - Key exchange (RSA, DHE, ECDHE)
    - Authentication (RSA, ECDSA)
    - Bulk encryption (AES-128, AES-256, ChaCha20)
    - Mode (CBC, GCM, CCM, Poly1305)
    - MAC (SHA, SHA256, SHA384, AEAD)

### 3.2 Cipher Suite Security Classification
- **Strong**: AES-256-GCM, ChaCha20-Poly1305
- **Acceptable**: AES-128-GCM
- **Weak**: CBC mode ciphers, 3DES
- **Insecure**: RC4, DES, NULL, EXPORT, ANON

### 3.3 Key Exchange Analysis
- RSA key exchange (flag as no forward secrecy)
- DHE parameters and group size
- ECDHE curves supported
- Named groups preference
- Static vs ephemeral key exchange

### 3.4 PQC Cipher Suite Requirements
- Detect ML-KEM key encapsulation support
- Identify KEM parameter sets (ML-KEM-512, 768, 1024)
- Check hybrid cipher suites (ECDHE + ML-KEM)
- Detect PQC-only vs hybrid modes
- Validate NIST-approved KEM algorithms
- Report key sizes and security equivalents
- Check for HNDL (Harvest Now Decrypt Later) protection

---

## 4. KEY EXCHANGE DEEP ANALYSIS

### 4.1 Diffie-Hellman Analysis
- DH parameter size (minimum 2048-bit)
- Detect common/weak DH groups
- Custom vs standard DH parameters
- DHE export grade detection

### 4.2 Elliptic Curve Analysis
- Supported curves enumeration
- Curve preference order
- Detect weak curves (P-192, sect163k1)
- Validate curve parameters
- Point format support

### 4.3 RSA Key Exchange
- RSA key size validation
- Detect RSA key exchange (no PFS)
- PKCS#1 v1.5 vs OAEP

### 4.4 PQC Key Exchange Requirements
- ML-KEM-512 support (NIST Level 1)
- ML-KEM-768 support (NIST Level 3)
- ML-KEM-1024 support (NIST Level 5)
- Hybrid mode detection:
    - X25519 + ML-KEM-768
    - P-256 + ML-KEM-768
    - P-384 + ML-KEM-1024
- Key encapsulation round-trip testing
- PQC handshake size measurement
- PQC handshake latency measurement

---

## 5. VULNERABILITY SCANNING

### 5.1 Protocol Vulnerabilities
- POODLE (SSLv3 CBC padding oracle)
- BEAST (TLS 1.0 CBC IV)
- CRIME (TLS compression)
- BREACH (HTTP compression)
- Lucky13 (CBC timing)
- Sweet32 (64-bit block cipher birthday)
- DROWN (SSLv2 cross-protocol)
- FREAK (RSA export downgrade)
- Logjam (DHE export downgrade)
- Raccoon (DH timing)

### 5.2 Implementation Vulnerabilities
- Heartbleed (OpenSSL memory disclosure)
- CCS Injection (OpenSSL ChangeCipherSpec)
- Ticketbleed (F5 session ticket)
- ROBOT (RSA padding oracle)
- Zombie POODLE/GOLDENDOODLE (CBC padding)
- Renegotiation vulnerability
- Secure renegotiation support

### 5.3 Certificate Vulnerabilities
- Weak signature algorithms (MD5, SHA-1)
- Short RSA keys (<2048 bits)
- Weak ECDSA curves
- Wildcard certificate misuse
- Hostname mismatch
- Expired certificates
- Not-yet-valid certificates

### 5.4 PQC Vulnerability Requirements
- Detect quantum-vulnerable key exchanges
- Flag RSA/ECDH-only configurations as future risk
- Identify HNDL exposure window
- Check for PQC algorithm implementation flaws
- Validate ML-KEM/ML-DSA parameter correctness
- Detect downgrade attacks on hybrid modes
- Check PQC implementation timing leaks

---

## 6. HTTP SECURITY HEADERS

### 6.1 Transport Security
- HSTS (Strict-Transport-Security)
    - max-age value
    - includeSubDomains directive
    - preload directive
    - Preload list membership
- HPKP (Public-Key-Pins) - deprecated but detect

### 6.2 Content Security
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

### 6.3 Cookie Security
- Secure flag on cookies
- HttpOnly flag
- SameSite attribute

---

## 7. DNS AND NETWORK ANALYSIS

### 7.1 DNS Security
- DNSSEC validation
- CAA records
- DANE/TLSA records
- MX record security (for mail servers)

### 7.2 Network Configuration
- IPv4 and IPv6 support
- SNI (Server Name Indication) requirement
- ALPN/NPN protocol negotiation
- Connection timeout behavior

---

## 8. COMPLIANCE CHECKING

### 8.1 Industry Standards
- PCI DSS requirements
- HIPAA guidelines
- NIST SP 800-52 Rev 2
- Mozilla SSL Configuration (Modern/Intermediate/Old)
- BSI TR-02102 (German federal)

### 8.2 CNSA 2.0 Compliance (NSA Requirements)
- 2025: Prefer CNSA 2.0 for firmware/software signing
- 2027: Support CNSA 2.0 for web servers/browsers
- 2030: Exclusively use CNSA 2.0 algorithms
- 2033: Prefer CNSA 2.0 for legacy equipment

### 8.3 PQC Compliance Requirements
- NIST FIPS 203 (ML-KEM) compliance
- NIST FIPS 204 (ML-DSA) compliance
- NIST FIPS 205 (SLH-DSA) compliance
- CNSA 2.0 algorithm support checklist
- Hybrid implementation validation
- Transition timeline readiness score

---

## 9. PERFORMANCE METRICS

### 9.1 Handshake Performance
- Full handshake latency
- Resumed handshake latency
- Time to first byte (TTFB)
- Connection setup overhead

### 9.2 PQC Performance Requirements
- PQC handshake additional latency
- PQC key size impact measurement
- Hybrid vs classical handshake comparison
- Bandwidth overhead calculation
- Server CPU impact estimation

---

## 10. REPORTING AND OUTPUT

### 10.1 Grading System
- A+: Exceptional configuration, PQC-ready
- A: Strong security, all modern standards
- B: Good security, minor issues
- C: Adequate security, improvements needed
- D: Weak security, significant issues
- E: Serious misconfigurations
- F: Critical vulnerabilities
- T: Certificate trust issues

### 10.2 PQC Readiness Score (Separate)
- PQC-Ready: Full hybrid PQC support
- PQC-Transitioning: Partial PQC support
- PQC-Aware: Server capable, not enabled
- PQC-Vulnerable: No PQC support, HNDL risk

### 10.3 Report Formats
- JSON structured output
- HTML formatted report
- PDF export
- CLI summary output
- API response format

### 10.4 Report Contents
- Executive summary
- Detailed findings per category
- Risk prioritization
- Remediation recommendations
- Historical comparison (if available)
- CNSA 2.0 compliance timeline gaps

---

## 11. SCANNING MODES

### 11.1 Scan Types
- Quick scan (basic checks)
- Full scan (comprehensive)
- PQC-focused scan
- Compliance-specific scan
- Custom scan (user-selected tests)

### 11.2 Target Types
- Single hostname
- Multiple hostnames (batch)
- IP address with SNI
- Port specification (default 443)
- STARTTLS protocols (SMTP, IMAP, POP3, FTP)

### 11.3 Scan Options
- Cache behavior (use cached/force new)
- Timeout configuration
- Retry logic
- Proxy support
- Rate limiting

---

## 12. ARCHITECTURE REQUIREMENTS

### 12.1 Core Components
- TLS handshake engine
- Certificate parser
- Cipher suite tester
- Vulnerability scanner
- PQC algorithm detector
- Report generator

### 12.2 PQC Library Integration
- ML-KEM implementation (FIPS 203)
- ML-DSA implementation (FIPS 204)
- Hybrid key exchange support
- liboqs or equivalent PQC library

### 12.3 Data Storage
- Scan result caching
- Historical data retention
- Configuration profiles

---

## 13. API REQUIREMENTS

### 13.1 Endpoints
- POST /scan - Initiate new scan
- GET /scan/{id} - Get scan status/results
- GET /scan/{id}/report - Get formatted report
- GET /grade/{hostname} - Quick grade lookup
- GET /pqc-readiness/{hostname} - PQC score only

### 13.2 Response Structure
- Scan ID
- Timestamp
- Target information
- Grade and PQC score
- Detailed findings array
- Recommendations array

---

## 14. TECHNOLOGY STACK RECOMMENDATIONS

### 14.1 Language Options
- Java (recommended for NoSneak integration)
- Python (for rapid prototyping)
- Go (for performance-critical components)

### 14.2 Libraries to Consider
- Bouncy Castle (Java - TLS and PQC support)
- liboqs (C library with Java bindings - PQC algorithms)
- OpenSSL 3.x (with oqsprovider for PQC)

### 14.3 Integration Points
- NoSneak platform integration
- REST API for external consumption
- CLI tool for command-line usage
- Web UI for browser-based access

---

## 15. IMPLEMENTATION PRIORITIES

### Phase 1: Core SSL Labs Equivalent
1. Certificate chain validation
2. Protocol version detection
3. Cipher suite enumeration
4. Basic vulnerability scanning
5. Grading engine

### Phase 2: PQC Scanning
1. ML-KEM detection
2. Hybrid key exchange detection
3. PQC certificate parsing
4. PQC readiness scoring
5. CNSA 2.0 compliance checking

### Phase 3: Advanced Features
1. Performance benchmarking
2. Historical tracking
3. Batch scanning
4. API and integrations
5. Comprehensive reporting

---

## Notes for Implementation
- This scanner should differentiate NoSneak from competitors by offering PQC readiness assessment
- Focus on CNSA 2.0 timeline compliance as key selling point
- Consider caching scan results to improve performance
- Ensure scanner itself uses secure, PQC-ready connections where possible
