package io.xlogistx.nosneak.ai.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

public class AICapture extends PropertyDAO {

    public enum Param implements GetNVConfig {
        FROM_AREA(NVConfigManager.createNVConfig("from_area", "name of the capture area it came from", "FromArea", false, true, String.class)),
        WIDTH(NVConfigManager.createNVConfig("width", "image width in pixels", "Width", false, true, Integer.class)),
        HEIGHT(NVConfigManager.createNVConfig("height", "image height in pixels", "Height", false, true, Integer.class)),
        NUM_BYTES(NVConfigManager.createNVConfig("num_bytes", "size of the stored png", "NumBytes", false, true, Integer.class)),
        THUMBNAIL(NVConfigManager.createNVConfig("thumbnail", "small png for list rows", "Thumbnail", false, true, byte[].class)),
        IMAGE(NVConfigManager.createNVConfig("image", "the full png bytes", "Image", false, true, byte[].class));

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_AI_CAPTURE = new NVConfigEntityPortable(
            "ai_capture", null, "AICapture", true, false, false, false,
            AICapture.class, SharedUtil.extractNVConfigs(Param.values()), null, false,
            PropertyDAO.NVC_PROPERTY_DAO
    );

    public AICapture() {
        super(NVC_AI_CAPTURE);
    }
    public String getFromArea() {
        return lookupValue(Param.FROM_AREA);
    }

    public void setFromArea(String fromArea) {
        setValue(Param.FROM_AREA, fromArea);
    }

    public int getWidth() {
        Integer width = lookupValue(Param.WIDTH);
        return width != null ? width : 0;
    }

    public void setWidth(int width) {
        setValue(Param.WIDTH, width);
    }

    public int getHeight() {
        Integer height = lookupValue(Param.HEIGHT);
        return height != null ? height : 0;
    }

    public void setHeight(int height) {
        setValue(Param.HEIGHT, height);
    }

    public int getNumBytes() {
        Integer numBytes = lookupValue(Param.NUM_BYTES);
        return numBytes != null ? numBytes : 0;
    }

    public void setNumBytes(int numBytes) {
        setValue(Param.NUM_BYTES, numBytes);
    }

    public byte[] getThumbnail() {
        return lookupValue(Param.THUMBNAIL);
    }

    public void setThumbnail(byte[] thumbnail) {
        setValue(Param.THUMBNAIL, thumbnail);
    }

    public byte[] getImage() {
        return lookupValue(Param.IMAGE);
    }

    public void setImage(byte[] image) {
        setValue(Param.IMAGE, image);
    }

}
