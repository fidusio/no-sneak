package io.xlogistx.nosneak.ai.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

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
