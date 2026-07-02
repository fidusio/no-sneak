package io.xlogistx.nosneak.nmap.service.probes;

import io.xlogistx.nosneak.nmap.service.ServiceMatch;
import io.xlogistx.nosneak.nmap.service.ServiceProbe;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * TLS/SSL detection probe.
 * Attempts TLS handshake to detect HTTPS and other TLS-wrapped services.
 */
public class TLSProbe implements ServiceProbe {

    @Override
    public String getName() {
        return "TLS";
    }

    @Override
    public int[] getDefaultPorts() {
        return new int[]{443, 8443, 993, 995, 465, 636, 989, 990};
    }

    @Override
    public String getProtocol() {
        return "tcp";
    }

    @Override
    public byte[] getProbeData() {
        // TLS ClientHello - minimal TLS 1.0 handshake
        return new byte[]{
            0x16,                   // Content type: Handshake
            0x03, 0x01,             // Version: TLS 1.0
            0x00, 0x2f,             // Length
            0x01,                   // Handshake type: ClientHello
            0x00, 0x00, 0x2b,       // Length
            0x03, 0x01,             // Client version: TLS 1.0
            // Random (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,                   // Session ID length
            0x00, 0x02,             // Cipher suites length
            0x00, 0x35,             // TLS_RSA_WITH_AES_256_CBC_SHA
            0x01,                   // Compression methods length
            0x00                    // null compression
        };
    }

    @Override
    public int getPriority() {
        return 75;
    }

    @Override
    public int getTimeoutMs() {
        return 3000; // TLS handshake needs more time
    }

    @Override
    public Optional<ServiceMatch> analyze(ByteBuffer response) {
        if (response == null || !response.hasRemaining()) {
            return Optional.empty();
        }

        byte[] bytes = new byte[response.remaining()];
        response.get(bytes);

        // Check for TLS response
        if (bytes.length < 5) {
            return Optional.empty();
        }

        // Check content type
        byte contentType = bytes[0];

        // Handshake (0x16), Alert (0x15), or Application Data (0x17)
        if (contentType != 0x16 && contentType != 0x15 && contentType != 0x17) {
            return Optional.empty();
        }

        // Check version bytes (should be 0x03 0x0X for SSLv3/TLS)
        if (bytes[1] != 0x03) {
            return Optional.empty();
        }

        ServiceMatch.Builder builder = ServiceMatch.builder("ssl/tls")
            .method("probed")
            .confidence(95);

        // Determine TLS version
        String version = getTlsVersion(bytes[2]);
        builder.version(version);

        // If handshake type is ServerHello (0x02), we have TLS
        if (contentType == 0x16 && bytes.length > 5 && bytes[5] == 0x02) {
            builder.extraInfo("ServerHello received");
        }

        // If alert (0x15), still TLS but might be rejecting our handshake
        if (contentType == 0x15) {
            builder.extraInfo("TLS Alert");
        }

        return Optional.of(builder.build());
    }

    private String getTlsVersion(byte minor) {
        switch (minor) {
            case 0x00: return "SSL 3.0";
            case 0x01: return "TLS 1.0";
            case 0x02: return "TLS 1.1";
            case 0x03: return "TLS 1.2";
            case 0x04: return "TLS 1.3";
            default: return "TLS";
        }
    }
}
