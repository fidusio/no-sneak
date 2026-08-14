package io.xlogistx.nosneak.ai.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

/**
 * A saved screenshot.
 * <p>
 * <b>The two byte fields are different formats.</b> {@code image} is the full-size PNG and
 * {@code numBytes} counts <i>it</i>; {@code thumbnail} is a <b>JPEG</b> (produced by
 * {@code GUIUtil.compressImage}, which also flattens alpha). Nothing reads either by extension,
 * so the mismatch is harmless in-app — but do not assume "PNG bytes" when exporting.
 * <p>
 * {@code fromArea} is a <b>copied label</b>, not a reference: the capture area it came from can be
 * renamed or deleted without affecting this row.
 * <p>
 * A capture sits outside the conversation model — it is not attached to a chat or a message. It
 * reaches a turn only by being wrapped in an {@link AISource}.
 * <p>
 * <b>Reads of this entity are usually projected.</b> Listing captures omits {@code image} because
 * it is heavy, so a row from a list has a thumbnail and a null PNG. Anything that <i>saves</i> a
 * capture must re-fetch the full row first, or the update writes that null over the stored image.
 */
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
