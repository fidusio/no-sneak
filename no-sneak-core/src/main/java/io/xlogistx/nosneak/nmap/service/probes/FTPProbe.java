package io.xlogistx.nosneak.nmap.service.probes;

import io.xlogistx.nosneak.nmap.service.ServiceMatch;
import io.xlogistx.nosneak.nmap.service.ServiceProbe;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * FTP service probe.
 * Passive probe that analyzes FTP banner.
 */
public class FTPProbe implements ServiceProbe {

    @Override
    public String getName() {
        return "FTP";
    }

    @Override
    public int[] getDefaultPorts() {
        return new int[]{21, 2121};
    }

    @Override
    public String getProtocol() {
        return "tcp";
    }

    @Override
    public byte[] getProbeData() {
        return null; // Passive - FTP servers send banner first
    }

    @Override
    public int getPriority() {
        return 85;
    }

    @Override
    public boolean isPassive() {
        return true;
    }

    @Override
    public Optional<ServiceMatch> analyze(ByteBuffer response) {
        if (response == null || !response.hasRemaining()) {
            return Optional.empty();
        }

        byte[] bytes = new byte[response.remaining()];
        response.get(bytes);
        String banner = new String(bytes, StandardCharsets.UTF_8).trim();

        // FTP banners start with 220
        if (!banner.startsWith("220")) {
            return Optional.empty();
        }

        ServiceMatch.Builder builder = ServiceMatch.builder("ftp")
            .method("banner")
            .confidence(95);

        String lower = banner.toLowerCase();

        // Identify FTP server
        if (lower.contains("vsftpd")) {
            builder.product("vsftpd");
            // Try to extract version
            int idx = lower.indexOf("vsftpd");
            String rest = banner.substring(idx + 6).trim();
            if (!rest.isEmpty()) {
                String[] parts = rest.split("\\s+");
                if (parts.length > 0 && parts[0].matches("[\\d.]+")) {
                    builder.version(parts[0]);
                }
            }
        } else if (lower.contains("proftpd")) {
            builder.product("ProFTPD");
        } else if (lower.contains("pure-ftpd")) {
            builder.product("Pure-FTPd");
        } else if (lower.contains("filezilla")) {
            builder.product("FileZilla Server");
        } else if (lower.contains("microsoft")) {
            builder.product("Microsoft FTP");
        } else if (lower.contains("wu-ftpd")) {
            builder.product("WU-FTPD");
        }

        return Optional.of(builder.build());
    }
}
