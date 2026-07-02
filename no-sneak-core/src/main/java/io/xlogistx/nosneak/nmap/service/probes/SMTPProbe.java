package io.xlogistx.nosneak.nmap.service.probes;

import io.xlogistx.nosneak.nmap.service.ServiceMatch;
import io.xlogistx.nosneak.nmap.service.ServiceProbe;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * SMTP service probe.
 * Passive probe that analyzes SMTP banner.
 */
public class SMTPProbe implements ServiceProbe {

    @Override
    public String getName() {
        return "SMTP";
    }

    @Override
    public int[] getDefaultPorts() {
        return new int[]{25, 465, 587, 2525};
    }

    @Override
    public String getProtocol() {
        return "tcp";
    }

    @Override
    public byte[] getProbeData() {
        return null; // Passive - SMTP servers send banner first
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

        // SMTP banners start with 220
        if (!banner.startsWith("220")) {
            return Optional.empty();
        }

        ServiceMatch.Builder builder = ServiceMatch.builder("smtp")
            .method("banner")
            .confidence(95);

        String lower = banner.toLowerCase();

        // Identify SMTP server
        if (lower.contains("postfix")) {
            builder.product("Postfix");
        } else if (lower.contains("sendmail")) {
            builder.product("Sendmail");
        } else if (lower.contains("exim")) {
            builder.product("Exim");
        } else if (lower.contains("microsoft") || lower.contains("exchange")) {
            builder.product("Microsoft Exchange");
        } else if (lower.contains("qmail")) {
            builder.product("qmail");
        } else if (lower.contains("haraka")) {
            builder.product("Haraka");
        } else if (lower.contains("gmail") || lower.contains("google")) {
            builder.product("Google SMTP");
        }

        // Try to determine if it's submission (587) vs regular SMTP
        // This is typically done by port, but we note it here
        if (lower.contains("esmtp")) {
            builder.extraInfo("ESMTP");
        }

        return Optional.of(builder.build());
    }
}
