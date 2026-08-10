package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.CaptureArea;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.SnapShot;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.model.AICapture;
import org.zoxweb.server.io.UByteArrayInputStream;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public final class CaptureSupport {

    static final String IMAGE_FORMAT = "png";
    static final int THUMBNAIL_EDGE = 200;

    private static final int SETTLE_MILLIS = 150;
    private static final DateTimeFormatter SHORT_TIME = DateTimeFormatter.ofPattern("HH:mm");

    private CaptureSupport() {
    }

    static RegionOverlay.Selection select(Window owner) throws Exception {
        hideWindow(owner);
        try {
            RegionOverlay.Selection selection = drag();
            return (selection != null && usable(selection.bounds())) ? selection : null;
        } finally {
            restoreWindow(owner);
        }
    }

    static SnapShot[] shootAndSave(AssistantContext ctx, Window owner, CaptureArea[] areas)
            throws Exception {
        hideWindow(owner);
        SnapShot[] snaps = new SnapShot[0];
        try {
            snaps = ctx.getCaptureAreaSet().takeSnapShots(areas);
            return snaps;
        } finally {
            for (SnapShot snap : snaps)
                ctx.saveCapture(toCapture(snap.getImage(),
                        snap.getSourceID() + " " + shortTime(snap.getTimestamp()), snap.getSourceID()));
            restoreWindow(owner);
        }
    }

    static UByteArrayInputStream toStream(BufferedImage image) throws IOException {
        return new SnapShot(null, 0, null, image).exportAsInputStream(IMAGE_FORMAT);
    }

    static AICapture toCapture(BufferedImage image, String name, String areaName) throws IOException {
        if (image == null) return null;

        byte[] png = toStream(image).readAllBytes();
        AICapture capture = new AICapture();
        capture.setName(name);
        capture.setFromArea(areaName);
        capture.setWidth(image.getWidth());
        capture.setHeight(image.getHeight());
        capture.setNumBytes(png.length);
        capture.setImage(png);
        capture.setThumbnail(GUIUtil.compressImage(image, THUMBNAIL_EDGE, GUIUtil.DEFAULT_JPG_QUALITY).readAllBytes());
        return capture;
    }

    static BufferedImage toImage(byte[] bytes) throws IOException {
        if (bytes == null || bytes.length == 0) return null;
        return ImageIO.read(new ByteArrayInputStream(bytes));
    }

    static String region(Rectangle area) {
        if (area == null) return "no area";
        return area.width + "x" + area.height + " at " + area.x + "," + area.y;
    }

    static boolean usable(Rectangle area) {
        return area != null && !area.isEmpty();
    }

    static ImageIcon scaledIcon(BufferedImage image, int maxWidth, int maxHeight) {
        double factor = Math.min(1.0, Math.min(
                (double) maxWidth / image.getWidth(), (double) maxHeight / image.getHeight()));
        int width = Math.max(1, (int) Math.round(image.getWidth() * factor));
        int height = Math.max(1, (int) Math.round(image.getHeight() * factor));
        return new ImageIcon(image.getScaledInstance(width, height, Image.SCALE_SMOOTH));
    }

    static String areaSublabel(CaptureArea area) {
        String region = region(area.getCaptureArea());
        String display = area.getDescription();
        return (display == null || display.isBlank()) ? region : display + "  ·  " + region;
    }

    static String bytes(int numBytes) {
        if (numBytes < 1024) return numBytes + " B";
        if (numBytes < 1024 * 1024) return (numBytes / 1024) + " KB";
        long tenths = Math.round(numBytes * 10.0 / (1024 * 1024));
        return (tenths / 10) + "." + (tenths % 10) + " MB";
    }

    static String shortTime(long millis) {
        return Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()).format(SHORT_TIME);
    }

    private static RegionOverlay.Selection drag() throws Exception {
        RegionOverlay.Selection selection = RegionOverlay.select();
        settle();
        return selection;
    }

    private static void hideWindow(Window window) throws Exception {
        if (window == null) return;
        SwingUtilities.invokeAndWait(() -> window.setVisible(false));
        settle();
    }

    private static void restoreWindow(Window window) {
        if (window == null) return;
        SwingUtilities.invokeLater(() -> {
            window.setVisible(true);
            window.toFront();
        });
    }

    private static void settle() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
        });
        Thread.sleep(SETTLE_MILLIS);
    }
}