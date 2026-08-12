package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.model.AICapture;
import io.xlogistx.nosneak.ai.model.AISource;
import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPResponseData;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

public final class SourceSupport {

    static final int MAX_TEXT_BYTES = 256 * 1024;
    static final String IMAGE_MEDIA_TYPE = "image/png";

    private static final String TRUNCATED = "\n\n... [truncated at " + (MAX_TEXT_BYTES / 1024) + " KB]";

    private SourceSupport() {
    }

    static AISource fromCapture(AICapture capture) {
        if (capture == null || capture.getGUID() == null) return null;

        AISource source = new AISource(AISource.SourceType.IMAGE, capture.getName());
        source.setCaptureGUID(capture.getGUID());
        source.setMediaType(IMAGE_MEDIA_TYPE);
        source.setNumBytes(capture.getNumBytes());
        source.setLocator(capture.getFromArea());
        return source;
    }

    static AISource fromFile(File file) throws IOException {
        byte[] raw = Files.readAllBytes(file.toPath());
        if (isBinary(raw)) throw new IOException("\"" + file.getName() + "\" is not a text file.");

        AISource source = new AISource(AISource.SourceType.FILE, file.getName());
        source.setLocator(file.getAbsolutePath());
        source.setMediaType(mediaType(file));
        source.setNumBytes(raw.length);
        source.setContent(text(raw));
        return source;
    }

    static AISource fromURL(String url) throws IOException {
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, null, HTTPMethod.GET);
        HTTPResponseData data = HTTPCall.send(hmci);

        if (!data.isSuccess()) throw new IOException(url + " returned status " + data.getStatus());

        String mediaType = mediaType(data.headerValue("content-type"));
        if (!isTextMediaType(mediaType))
            throw new IOException(url + " returned " + mediaType + ", which is not text.");

        byte[] raw = data.getData();
        String content = text(raw);
        if (mediaType.startsWith("text/html")) content = stripHTML(content);

        AISource source = new AISource(AISource.SourceType.URL, host(url));
        source.setLocator(url);
        source.setMediaType(mediaType);
        source.setNumBytes(raw != null ? raw.length : 0);
        source.setContent(content);
        return source;
    }

    static AISource fromText(String text, String name) {
        AISource source = new AISource(AISource.SourceType.TEXT, name);
        source.setMediaType("text/plain");
        source.setNumBytes(text != null ? text.getBytes(StandardCharsets.UTF_8).length : 0);
        source.setContent(text);
        return source;
    }

    static String block(List<AISource> sources) {
        StringBuilder sb = new StringBuilder();
        for (AISource source : sources) {
            String content = source.getContent();
            if (content == null || content.isBlank()) continue;
            if (!sb.isEmpty()) sb.append("\n\n");
            sb.append("<source name=\"").append(escape(source.getName())).append("\"");
            if (source.getSourceType() != null)
                sb.append(" type=\"").append(source.getSourceType().getName()).append("\"");
            if (source.getLocator() != null)
                sb.append(" from=\"").append(escape(source.getLocator())).append("\"");
            sb.append(">\n").append(content).append("\n</source>");
        }
        return sb.toString();
    }

    static String sublabel(AISource source) {
        StringBuilder sb = new StringBuilder();
        if (source.getSourceType() != null) sb.append(source.getSourceType().getName());
        if (source.getLocator() != null) sb.append("  ·  ").append(source.getLocator());
        if (source.getNumBytes() > 0) sb.append("  ·  ").append(CaptureSupport.bytes(source.getNumBytes()));
        return sb.toString();
    }

    static String stripHTML(String html) {
        if (html == null) return null;
        String out = html.replaceAll("(?is)<(script|style)[^>]*>.*?</\\1>", " ");
        out = out.replaceAll("(?s)<[^>]+>", " ");
        out = out.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<")
                .replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'");
        return out.replaceAll("[ \\t]+", " ").replaceAll("(?m)^ +| +$", "").replaceAll("\n{3,}", "\n\n").trim();
    }

    static String mediaType(File file) {
        try {
            String probed = Files.probeContentType(file.toPath());
            if (probed != null) return probed;
        } catch (IOException e) {
            return byExtension(file);
        }
        return byExtension(file);
    }

    private static String byExtension(File file) {
        String name = file.getName().toLowerCase();
        if (name.endsWith(".json")) return "application/json";
        if (name.endsWith(".xml")) return "application/xml";
        if (name.endsWith(".html") || name.endsWith(".htm")) return "text/html";
        if (name.endsWith(".csv")) return "text/csv";
        if (name.endsWith(".png")) return "image/png";
        if (name.endsWith(".jpg") || name.endsWith(".jpeg")) return "image/jpeg";
        if (name.endsWith(".gif")) return "image/gif";
        if (name.endsWith(".bmp")) return "image/bmp";
        return "text/plain";
    }

    static boolean isTextMediaType(String mediaType) {
        if (mediaType == null) return false;
        return mediaType.startsWith("text/")
                || mediaType.startsWith("application/json")
                || mediaType.startsWith("application/xml")
                || mediaType.startsWith("application/x-yaml")
                || mediaType.endsWith("+json")
                || mediaType.endsWith("+xml");
    }

    static boolean isImageFile(File file) {
        String mediaType = mediaType(file);
        return mediaType != null && mediaType.startsWith("image/");
    }

    private static String text(byte[] raw) {
        if (raw == null || raw.length == 0) return "";
        if (raw.length <= MAX_TEXT_BYTES) return new String(raw, StandardCharsets.UTF_8);
        return new String(raw, 0, MAX_TEXT_BYTES, StandardCharsets.UTF_8) + TRUNCATED;
    }

    private static boolean isBinary(byte[] raw) {
        int scanned = Math.min(raw.length, 8192);
        for (int i = 0; i < scanned; i++)
            if (raw[i] == 0) return true;
        return false;
    }

    private static String mediaType(String contentType) {
        if (contentType == null) return "application/octet-stream";
        int semicolon = contentType.indexOf(';');
        return (semicolon < 0 ? contentType : contentType.substring(0, semicolon)).trim().toLowerCase();
    }

    private static String host(String url) {
        try {
            String host = java.net.URI.create(url).getHost();
            return (host != null) ? host : url;
        } catch (Exception e) {
            return url;
        }
    }

    private static String escape(String value) {
        return (value == null) ? "" : value.replace("\"", "'");
    }
}