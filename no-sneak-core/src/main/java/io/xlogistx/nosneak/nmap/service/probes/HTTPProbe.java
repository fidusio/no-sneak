package io.xlogistx.nosneak.nmap.service.probes;

import io.xlogistx.nosneak.nmap.service.ServiceMatch;
import io.xlogistx.nosneak.nmap.service.ServiceProbe;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * HTTP service probe.
 * Sends a minimal HTTP request and analyzes the response.
 */
public class HTTPProbe implements ServiceProbe {

    private static final Pattern SERVER_PATTERN = Pattern.compile(
        "Server:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);

    private static final Pattern VERSION_PATTERN = Pattern.compile(
        "([\\w-]+)/([\\d.]+)");

    private static final String HTTP_REQUEST =
        "GET / HTTP/1.0\r\n" +
        "Host: localhost\r\n" +
        "User-Agent: XNMap/1.0\r\n" +
        "Accept: */*\r\n" +
        "Connection: close\r\n" +
        "\r\n";

    @Override
    public String getName() {
        return "HTTP";
    }

    @Override
    public int[] getDefaultPorts() {
        return new int[]{80, 8080, 8000, 8888, 3000, 5000, 8008};
    }

    @Override
    public String getProtocol() {
        return "tcp";
    }

    @Override
    public byte[] getProbeData() {
        return HTTP_REQUEST.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public int getPriority() {
        return 80;
    }

    @Override
    public Optional<ServiceMatch> analyze(ByteBuffer response) {
        if (response == null || !response.hasRemaining()) {
            return Optional.empty();
        }

        byte[] bytes = new byte[response.remaining()];
        response.get(bytes);
        String data = new String(bytes, StandardCharsets.UTF_8);

        // Check if it's an HTTP response
        if (!data.startsWith("HTTP/")) {
            // Could still be HTTP if it contains HTML
            if (data.toLowerCase().contains("<!doctype html") ||
                data.toLowerCase().contains("<html")) {
                return Optional.of(ServiceMatch.builder("http")
                    .method("probed")
                    .confidence(70)
                    .build());
            }
            return Optional.empty();
        }

        ServiceMatch.Builder builder = ServiceMatch.builder("http")
            .method("probed")
            .confidence(100);

        // Extract Server header
        Matcher serverMatcher = SERVER_PATTERN.matcher(data);
        if (serverMatcher.find()) {
            String server = serverMatcher.group(1).trim();

            // Parse product and version
            Matcher versionMatcher = VERSION_PATTERN.matcher(server);
            if (versionMatcher.find()) {
                builder.product(versionMatcher.group(1));
                builder.version(versionMatcher.group(2));
            } else {
                builder.product(server);
            }

            // Detect specific products
            String lower = server.toLowerCase();
            if (lower.contains("apache")) {
                builder.product("Apache httpd");
            } else if (lower.contains("nginx")) {
                builder.product("nginx");
            } else if (lower.contains("iis")) {
                builder.product("Microsoft IIS");
            } else if (lower.contains("lighttpd")) {
                builder.product("lighttpd");
            } else if (lower.contains("tomcat")) {
                builder.product("Apache Tomcat");
            } else if (lower.contains("jetty")) {
                builder.product("Jetty");
            }
        }

        return Optional.of(builder.build());
    }
}
