package io.xlogistx.nosneak.nmap.service.probes;

import io.xlogistx.nosneak.nmap.service.ServiceMatch;
import io.xlogistx.nosneak.nmap.service.ServiceProbe;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SSH service probe.
 * SSH is banner-based, so this is primarily a passive probe.
 */
public class SSHProbe implements ServiceProbe {

    private static final Pattern SSH_BANNER = Pattern.compile(
        "SSH-([12]\\.[0-9]+)-([^\\s\\r\\n]+)(?:\\s+(.+))?");

    @Override
    public String getName() {
        return "SSH";
    }

    @Override
    public int[] getDefaultPorts() {
        return new int[]{22, 2222, 22222};
    }

    @Override
    public String getProtocol() {
        return "tcp";
    }

    @Override
    public byte[] getProbeData() {
        // SSH is banner-based, send our own banner to get response
        return "SSH-2.0-XNMap_Scanner\r\n".getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public int getPriority() {
        return 90;
    }

    @Override
    public Optional<ServiceMatch> analyze(ByteBuffer response) {
        if (response == null || !response.hasRemaining()) {
            return Optional.empty();
        }

        byte[] bytes = new byte[response.remaining()];
        response.get(bytes);
        String banner = new String(bytes, StandardCharsets.UTF_8).trim();

        if (!banner.startsWith("SSH-")) {
            return Optional.empty();
        }

        ServiceMatch.Builder builder = ServiceMatch.builder("ssh")
            .method("probed")
            .confidence(100);

        Matcher m = SSH_BANNER.matcher(banner);
        if (m.find()) {
            String protocol = m.group(1);
            String impl = m.group(2);
            String comments = m.group(3);

            builder.extraInfo("protocol " + protocol);

            // Parse implementation
            if (impl.toLowerCase().contains("openssh")) {
                builder.product("OpenSSH");
                int idx = impl.indexOf('_');
                if (idx > 0) {
                    builder.version(impl.substring(idx + 1));
                }
            } else if (impl.toLowerCase().contains("dropbear")) {
                builder.product("Dropbear");
                int idx = impl.indexOf('_');
                if (idx > 0) {
                    builder.version(impl.substring(idx + 1));
                }
            } else if (impl.toLowerCase().contains("libssh")) {
                builder.product("libssh");
            } else {
                builder.product(impl);
            }

            // Extract OS hints from comments
            if (comments != null) {
                String lower = comments.toLowerCase();
                if (lower.contains("ubuntu")) {
                    builder.osType("Linux");
                    builder.extraInfo(comments.trim());
                } else if (lower.contains("debian")) {
                    builder.osType("Linux");
                } else if (lower.contains("raspbian")) {
                    builder.osType("Linux");
                }
            }
        }

        return Optional.of(builder.build());
    }
}
