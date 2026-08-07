package io.xlogistx.nosneak.ai.assistant.panels;

import java.awt.Rectangle;
import java.awt.image.BufferedImage;

public class ScreenCapture {

    private String name;
    private Rectangle area;
    private BufferedImage image;
    private long timestamp;

    public ScreenCapture() {
    }

    public ScreenCapture(Rectangle area) {
        this.area = area;
    }

    public ScreenCapture(Rectangle area, BufferedImage image) {
        this.area = area;
        this.image = image;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Rectangle getArea() {
        return area;
    }

    public void setArea(Rectangle area) {
        this.area = area;
    }

    public BufferedImage getImage() {
        return image;
    }

    public void setImage(BufferedImage image) {
        this.image = image;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
}