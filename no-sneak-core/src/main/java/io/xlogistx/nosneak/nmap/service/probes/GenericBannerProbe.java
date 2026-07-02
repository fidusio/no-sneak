package io.xlogistx.nosneak.nmap.service.probes;

import io.xlogistx.nosneak.nmap.service.ServiceMatch;
import io.xlogistx.nosneak.nmap.service.ServiceProbe;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generic banner probe - passive, just reads initial banner.
 * Tries to identify service from common banner patterns.
 */
public class GenericBannerProbe implements ServiceProbe {

    private static final Pattern SSH_PATTERN = Pattern.compile(
        "SSH-([\\d.]+)-([^\\s]+)(?:\\s+(.+))?", Pattern.CASE_INSENSITIVE);

    private static final Pattern FTP_PATTERN = Pattern.compile(
        "^220[- ](.+)$", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);

    private static final Pattern SMTP_PATTERN = Pattern.compile(
        "^220[- ](.+)$", Pattern.MULTILINE);

    private static final Pattern POP3_PATTERN = Pattern.compile(
        "^\\+OK (.+)$", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);

    private static final Pattern IMAP_PATTERN = Pattern.compile(
        "^\\* OK (.+)$", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() {
        return "GenericBanner";
    }

    @Override
    public int[] getDefaultPorts() {
        return new int[]{}; // Applies to all ports
    }

    @Override
    public String getProtocol() {
        return "tcp";
    }

    @Override
    public byte[] getProbeData() {
        return null; // Passive probe
    }

    @Override
    public int getPriority() {
        return 100; // Highest priority - try first
    }

    @Override
    public Optional<ServiceMatch> analyze(ByteBuffer response) {
        if (response == null || !response.hasRemaining()) {
            return Optional.empty();
        }

        byte[] bytes = new byte[response.remaining()];
        response.get(bytes);
        String banner = new String(bytes, StandardCharsets.UTF_8).trim();

        if (banner.isEmpty()) {
            return Optional.empty();
        }

        // Try SSH
        if (banner.startsWith("SSH-")) {
            return parseSSH(banner);
        }

        // Try FTP (220 response)
        if (banner.startsWith("220") && (banner.toLowerCase().contains("ftp") ||
            banner.toLowerCase().contains("filezilla") ||
            banner.toLowerCase().contains("vsftpd") ||
            banner.toLowerCase().contains("proftpd"))) {
            return parseFTP(banner);
        }

        // Try SMTP (220 response with mail keywords)
        if (banner.startsWith("220") && (banner.toLowerCase().contains("smtp") ||
            banner.toLowerCase().contains("mail") ||
            banner.toLowerCase().contains("postfix") ||
            banner.toLowerCase().contains("sendmail") ||
            banner.toLowerCase().contains("exim"))) {
            return parseSMTP(banner);
        }

        // Try POP3
        if (banner.startsWith("+OK")) {
            return parsePOP3(banner);
        }

        // Try IMAP
        if (banner.startsWith("* OK")) {
            return parseIMAP(banner);
        }

        // Try MySQL
        if (isMySQL(bytes)) {
            return Optional.of(ServiceMatch.builder("mysql")
                .method("banner").confidence(90).build());
        }

        // Try Redis
        if (banner.startsWith("-ERR") || banner.startsWith("+PONG") ||
            banner.startsWith("$") || banner.startsWith("*")) {
            return Optional.of(ServiceMatch.builder("redis")
                .method("banner").confidence(80).build());
        }

        // Try MongoDB
        if (banner.contains("MongoDB") || isMongoDB(bytes)) {
            return Optional.of(ServiceMatch.builder("mongodb")
                .method("banner").confidence(80).build());
        }

        return Optional.empty();
    }

    private Optional<ServiceMatch> parseSSH(String banner) {
        Matcher m = SSH_PATTERN.matcher(banner);
        if (m.find()) {
            String protocol = m.group(1);
            String impl = m.group(2);
            String extra = m.group(3);

            ServiceMatch.Builder builder = ServiceMatch.builder("ssh")
                .method("banner")
                .confidence(100);

            if (impl.toLowerCase().contains("openssh")) {
                builder.product("OpenSSH");
                // Extract version after underscore
                int idx = impl.indexOf('_');
                if (idx > 0) {
                    String version = impl.substring(idx + 1);
                    // Clean up version (remove trailing stuff like p1)
                    builder.version(version);
                }
            } else if (impl.toLowerCase().contains("dropbear")) {
                builder.product("Dropbear");
            } else {
                builder.product(impl);
            }

            if (extra != null) {
                builder.extraInfo(extra.trim());
            }

            return Optional.of(builder.build());
        }

        return Optional.of(ServiceMatch.builder("ssh").method("banner").build());
    }

    private Optional<ServiceMatch> parseFTP(String banner) {
        ServiceMatch.Builder builder = ServiceMatch.builder("ftp")
            .method("banner")
            .confidence(90);

        String lower = banner.toLowerCase();
        if (lower.contains("vsftpd")) {
            builder.product("vsftpd");
        } else if (lower.contains("proftpd")) {
            builder.product("ProFTPD");
        } else if (lower.contains("filezilla")) {
            builder.product("FileZilla");
        } else if (lower.contains("pure-ftpd")) {
            builder.product("Pure-FTPd");
        } else if (lower.contains("microsoft")) {
            builder.product("Microsoft FTP");
        }

        return Optional.of(builder.build());
    }

    private Optional<ServiceMatch> parseSMTP(String banner) {
        ServiceMatch.Builder builder = ServiceMatch.builder("smtp")
            .method("banner")
            .confidence(90);

        String lower = banner.toLowerCase();
        if (lower.contains("postfix")) {
            builder.product("Postfix");
        } else if (lower.contains("sendmail")) {
            builder.product("Sendmail");
        } else if (lower.contains("exim")) {
            builder.product("Exim");
        } else if (lower.contains("microsoft") || lower.contains("exchange")) {
            builder.product("Microsoft Exchange");
        }

        return Optional.of(builder.build());
    }

    private Optional<ServiceMatch> parsePOP3(String banner) {
        ServiceMatch.Builder builder = ServiceMatch.builder("pop3")
            .method("banner")
            .confidence(90);

        String lower = banner.toLowerCase();
        if (lower.contains("dovecot")) {
            builder.product("Dovecot");
        } else if (lower.contains("courier")) {
            builder.product("Courier");
        }

        return Optional.of(builder.build());
    }

    private Optional<ServiceMatch> parseIMAP(String banner) {
        ServiceMatch.Builder builder = ServiceMatch.builder("imap")
            .method("banner")
            .confidence(90);

        String lower = banner.toLowerCase();
        if (lower.contains("dovecot")) {
            builder.product("Dovecot");
        } else if (lower.contains("courier")) {
            builder.product("Courier");
        } else if (lower.contains("cyrus")) {
            builder.product("Cyrus");
        }

        return Optional.of(builder.build());
    }

    private boolean isMySQL(byte[] data) {
        // MySQL protocol starts with packet length (3 bytes) + sequence (1 byte)
        // followed by protocol version (0x0a for MySQL 5.x)
        if (data.length > 5) {
            return data[4] == 0x0a || data[4] == 0x09;
        }
        return false;
    }

    private boolean isMongoDB(byte[] data) {
        // MongoDB wire protocol check
        if (data.length >= 16) {
            // Check for OP_MSG or OP_REPLY opcodes
            int opcode = (data[12] & 0xFF) | ((data[13] & 0xFF) << 8) |
                        ((data[14] & 0xFF) << 16) | ((data[15] & 0xFF) << 24);
            return opcode == 1 || opcode == 2013 || opcode == 2004;
        }
        return false;
    }
}
