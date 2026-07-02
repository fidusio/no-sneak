package io.xlogistx.nosneak.scanners;

/**
 * Configuration options for PQC scanning.
 * Controls optional features like revocation checking, cipher enumeration, and protocol version testing.
 */
public class PQCScanOptions {

    // Default timeout values
    public static final int DEFAULT_CONNECT_TIMEOUT_MS = 10000;
    public static final int DEFAULT_REVOCATION_TIMEOUT_MS = 5000;
    public static final int DEFAULT_ENUMERATION_TIMEOUT_MS = 3000;

    // Revocation checking options
    private boolean checkRevocation;
    private int revocationTimeoutMs;

    // Cipher enumeration options
    private boolean enumerateCiphers;
    private boolean includeWeakCiphers;
    private boolean includeInsecureCiphers;

    // Protocol version testing options
    private boolean testProtocolVersions;
    private boolean testSSLv3;
    private boolean testTLS10;
    private boolean testTLS11;

    // General options
    private int connectTimeoutMs;
    private int enumerationTimeoutMs;

    private PQCScanOptions() {
        // Set defaults
        this.checkRevocation = false;
        this.revocationTimeoutMs = DEFAULT_REVOCATION_TIMEOUT_MS;
        this.enumerateCiphers = false;
        this.includeWeakCiphers = false;
        this.includeInsecureCiphers = false;
        this.testProtocolVersions = false;
        this.testSSLv3 = false;
        this.testTLS10 = true;
        this.testTLS11 = true;
        this.connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        this.enumerationTimeoutMs = DEFAULT_ENUMERATION_TIMEOUT_MS;
    }

    /**
     * Create a new builder for PQCScanOptions.
     *
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Create default options with no extra features enabled.
     *
     * @return default PQCScanOptions
     */
    public static PQCScanOptions defaults() {
        return new Builder().build();
    }

    /**
     * Create options with all features enabled for comprehensive scanning.
     *
     * @return comprehensive PQCScanOptions
     */
    public static PQCScanOptions comprehensive() {
        return new Builder()
                .checkRevocation(true)
                .enumerateCiphers(true)
                .includeWeakCiphers(true)
                .testProtocolVersions(true)
                .testSSLv3(true)
                .build();
    }

    // Getters
    public boolean isCheckRevocation() {
        return checkRevocation;
    }

    public int getRevocationTimeoutMs() {
        return revocationTimeoutMs;
    }

    public boolean isEnumerateCiphers() {
        return enumerateCiphers;
    }

    public boolean isIncludeWeakCiphers() {
        return includeWeakCiphers;
    }

    public boolean isIncludeInsecureCiphers() {
        return includeInsecureCiphers;
    }

    public boolean isTestProtocolVersions() {
        return testProtocolVersions;
    }

    public boolean isTestSSLv3() {
        return testSSLv3;
    }

    public boolean isTestTLS10() {
        return testTLS10;
    }

    public boolean isTestTLS11() {
        return testTLS11;
    }

    public int getConnectTimeoutMs() {
        return connectTimeoutMs;
    }

    public int getEnumerationTimeoutMs() {
        return enumerationTimeoutMs;
    }

    @Override
    public String toString() {
        return "PQCScanOptions{" +
                "checkRevocation=" + checkRevocation +
                ", revocationTimeoutMs=" + revocationTimeoutMs +
                ", enumerateCiphers=" + enumerateCiphers +
                ", includeWeakCiphers=" + includeWeakCiphers +
                ", includeInsecureCiphers=" + includeInsecureCiphers +
                ", testProtocolVersions=" + testProtocolVersions +
                ", testSSLv3=" + testSSLv3 +
                ", testTLS10=" + testTLS10 +
                ", testTLS11=" + testTLS11 +
                ", connectTimeoutMs=" + connectTimeoutMs +
                ", enumerationTimeoutMs=" + enumerationTimeoutMs +
                '}';
    }

    /**
     * Builder for PQCScanOptions.
     */
    public static class Builder {
        private final PQCScanOptions options;

        public Builder() {
            this.options = new PQCScanOptions();
        }

        /**
         * Enable or disable certificate revocation checking via CRL/OCSP.
         *
         * @param check true to enable revocation checking
         * @return this builder
         */
        public Builder checkRevocation(boolean check) {
            options.checkRevocation = check;
            return this;
        }

        /**
         * Set the timeout for revocation checking (CRL download, OCSP requests).
         *
         * @param timeoutMs timeout in milliseconds
         * @return this builder
         */
        public Builder revocationTimeoutMs(int timeoutMs) {
            options.revocationTimeoutMs = timeoutMs;
            return this;
        }

        /**
         * Enable or disable cipher suite enumeration.
         *
         * @param enumerate true to enumerate all supported cipher suites
         * @return this builder
         */
        public Builder enumerateCiphers(boolean enumerate) {
            options.enumerateCiphers = enumerate;
            return this;
        }

        /**
         * Include weak cipher suites in enumeration (3DES, RC4, etc.).
         *
         * @param include true to include weak ciphers
         * @return this builder
         */
        public Builder includeWeakCiphers(boolean include) {
            options.includeWeakCiphers = include;
            return this;
        }

        /**
         * Include insecure cipher suites in enumeration (NULL, export, DES, etc.).
         * Warning: Testing insecure ciphers may reveal significant vulnerabilities.
         *
         * @param include true to include insecure ciphers
         * @return this builder
         */
        public Builder includeInsecureCiphers(boolean include) {
            options.includeInsecureCiphers = include;
            return this;
        }

        /**
         * Enable or disable protocol version testing.
         *
         * @param test true to test supported protocol versions
         * @return this builder
         */
        public Builder testProtocolVersions(boolean test) {
            options.testProtocolVersions = test;
            return this;
        }

        /**
         * Test for SSLv3 support (known vulnerable protocol).
         *
         * @param test true to test SSLv3
         * @return this builder
         */
        public Builder testSSLv3(boolean test) {
            options.testSSLv3 = test;
            return this;
        }

        /**
         * Test for TLS 1.0 support (deprecated protocol).
         *
         * @param test true to test TLS 1.0
         * @return this builder
         */
        public Builder testTLS10(boolean test) {
            options.testTLS10 = test;
            return this;
        }

        /**
         * Test for TLS 1.1 support (deprecated protocol).
         *
         * @param test true to test TLS 1.1
         * @return this builder
         */
        public Builder testTLS11(boolean test) {
            options.testTLS11 = test;
            return this;
        }

        /**
         * Set the connection timeout for all scan operations.
         *
         * @param timeoutMs timeout in milliseconds
         * @return this builder
         */
        public Builder connectTimeoutMs(int timeoutMs) {
            options.connectTimeoutMs = timeoutMs;
            return this;
        }

        /**
         * Set the timeout for individual cipher/protocol enumeration attempts.
         *
         * @param timeoutMs timeout in milliseconds
         * @return this builder
         */
        public Builder enumerationTimeoutMs(int timeoutMs) {
            options.enumerationTimeoutMs = timeoutMs;
            return this;
        }

        /**
         * Build the PQCScanOptions.
         *
         * @return the configured PQCScanOptions
         */
        public PQCScanOptions build() {
            return options;
        }
    }
}
