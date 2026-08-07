package io.xlogistx.nosneak.ai.assistant;

import java.awt.*;

public class CaptureArea {
    private String name;
    private Rectangle bounds;
    private long lastUsed;

    public CaptureArea() {

    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Rectangle getBounds() {
        return bounds;
    }

    public void setBounds(Rectangle bounds) {
        this.bounds = bounds;
    }

    public long getLastUsed() {
        return lastUsed;
    }

    public void setLastUsed(long lastUsed) {
        this.lastUsed = lastUsed;
    }
}
