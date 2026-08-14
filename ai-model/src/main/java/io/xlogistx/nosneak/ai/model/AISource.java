package io.xlogistx.nosneak.ai.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

/**
 * Something attached to a message: a file's text, a URL's text, pasted text, or an image.
 * <p>
 * Which fields are populated depends on {@link SourceType}, and the combinations are not
 * interchangeable:
 * <ul>
 *   <li>{@code FILE} / {@code URL} — {@code locator} is the path or URL, {@code content} is the
 *       extracted text.</li>
 *   <li>{@code TEXT} — {@code content} only; there is no locator, because nothing on disk
 *       corresponds to it.</li>
 *   <li>{@code IMAGE} — {@code content} is null and {@code captureGUID} points at the
 *       {@link AICapture} holding the bytes. The pixels are <b>never</b> stored here.</li>
 * </ul>
 * Text sources are flattened into the outgoing prompt; image sources are resolved through their
 * capture and sent as image parts.
 */
public class AISource extends PropertyDAO {

    public enum SourceType implements GetName {
        FILE("file"), URL("url"), TEXT("text"), IMAGE("image");
        private final String name;

        SourceType(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    public enum Param implements GetNVConfig {
        SOURCE_TYPE(NVConfigManager.createNVConfig("source_type", "where the source came from", "SourceType", true, true, SourceType.class)),
        LOCATOR(NVConfigManager.createNVConfig("locator", "absolute path or url; null for pasted text", "Locator", false, true, String.class)),
        CONTENT(NVConfigManager.createNVConfig("content", "extracted text; null for an image source", "Content", false, true, String.class)),
        CAPTURE_GUID(NVConfigManager.createNVConfig("capture_guid", "the AICapture holding the bytes; null for a text source", "CaptureGUID", false, true, String.class)),
        MEDIA_TYPE(NVConfigManager.createNVConfig("media_type", "media type of the original", "MediaType", false, true, String.class)),
        NUM_BYTES(NVConfigManager.createNVConfig("num_bytes", "size of the original", "NumBytes", false, true, Integer.class));

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_AI_SOURCE = new NVConfigEntityPortable(
            "ai_source", null, "AISource", true, false, false, false,
            AISource.class, SharedUtil.extractNVConfigs(Param.values()), null, false,
            PropertyDAO.NVC_PROPERTY_DAO
    );

    public AISource() {
        super(NVC_AI_SOURCE);
    }

    public AISource(SourceType sourceType, String name) {
        this();
        setSourceType(sourceType);
        setName(name);
    }

    public SourceType getSourceType() {
        return lookupValue(Param.SOURCE_TYPE);
    }

    public void setSourceType(SourceType sourceType) {
        setValue(Param.SOURCE_TYPE, sourceType);
    }

    public String getLocator() {
        return lookupValue(Param.LOCATOR);
    }

    public void setLocator(String locator) {
        setValue(Param.LOCATOR, locator);
    }

    public String getContent() {
        return lookupValue(Param.CONTENT);
    }

    public void setContent(String content) {
        setValue(Param.CONTENT, content);
    }

    public String getCaptureGUID() {
        return lookupValue(Param.CAPTURE_GUID);
    }

    public void setCaptureGUID(String captureGUID) {
        setValue(Param.CAPTURE_GUID, captureGUID);
    }

    public String getMediaType() {
        return lookupValue(Param.MEDIA_TYPE);
    }

    public void setMediaType(String mediaType) {
        setValue(Param.MEDIA_TYPE, mediaType);
    }

    public int getNumBytes() {
        Integer numBytes = lookupValue(Param.NUM_BYTES);
        return numBytes != null ? numBytes : 0;
    }

    public void setNumBytes(int numBytes) {
        setValue(Param.NUM_BYTES, numBytes);
    }

    public boolean isImage() {
        return getSourceType() == SourceType.IMAGE;
    }
}
