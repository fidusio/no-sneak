package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.GUIUtil;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.assistant.CaptureArea;
import io.xlogistx.nosneak.ai.model.AICapture;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public final class CaptureSupport {

    record ShootResult(int saved, List<String> failures) {
    }

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

    static BufferedImage shoot(Window owner, Rectangle preset) throws Exception {
        hideWindow(owner);
        try {
            Rectangle area = preset;
            if (area == null) {
                RegionOverlay.Selection selection = drag();
                area = (selection != null) ? selection.bounds() : null;
            }
            if (!usable(area)) return null;
            return GUIUtil.captureSelectedArea(area);
        } finally {
            restoreWindow(owner);
        }
    }

    static ShootResult shootAll(AssistantContext ctx, Window owner, List<CaptureArea> areas, long now)
            throws Exception {
        int saved = 0;
        List<String> failures = new ArrayList<>();
        hideWindow(owner);
        try {
            Robot robot = new Robot();
            for (CaptureArea area : areas) {
                try {
                    if (!usable(area.getBounds()))
                        throw new IllegalStateException("area has no usable bounds");
                    BufferedImage shot = robot.createScreenCapture(area.getBounds());
                    ctx.saveCapture(toCapture(shot, area.getName() + " " + shortTime(now), area.getName()));
                    area.setLastUsed(now);
                    saved++;
                } catch (Exception e) {
                    failures.add(area.getName() + ": " + e.getMessage());
                }
            }
        } finally {
            restoreWindow(owner);
        }
        return new ShootResult(saved, failures);
    }

    static AICapture toCapture(BufferedImage image, String name, String areaName) throws IOException {
        if (image == null) return null;

        byte[] png = toPNG(image);
        AICapture capture = new AICapture();
        capture.setName(name);
        capture.setFromArea(areaName);
        capture.setWidth(image.getWidth());
        capture.setHeight(image.getHeight());
        capture.setNumBytes(png.length);
        capture.setImage(png);
        capture.setThumbnail(toPNG(scale(image, THUMBNAIL_EDGE)));
        return capture;
    }

    static byte[] toPNG(BufferedImage image) throws IOException {
        if (image == null) return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (!ImageIO.write(image, IMAGE_FORMAT, out))
            throw new IOException("cannot encode the image as " + IMAGE_FORMAT);
        return out.toByteArray();
    }

    static BufferedImage toImage(byte[] png) throws IOException {
        if (png == null || png.length == 0) return null;
        return ImageIO.read(new ByteArrayInputStream(png));
    }

    static BufferedImage scale(BufferedImage image, int maxEdge) {
        if (image == null) return null;

        int longest = Math.max(image.getWidth(), image.getHeight());
        if (longest <= maxEdge) return image;

        double factor = (double) maxEdge / longest;
        int width = Math.max(1, (int) Math.round(image.getWidth() * factor));
        int height = Math.max(1, (int) Math.round(image.getHeight() * factor));

        BufferedImage scaled = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = scaled.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
            g.drawImage(image, 0, 0, width, height, null);
        } finally {
            g.dispose();
        }
        return scaled;
    }

    static String region(Rectangle area) {
        if (area == null) return "no area";
        return area.width + "x" + area.height + " at " + area.x + "," + area.y;
    }

    static boolean usable(Rectangle area) {
        return area != null && area.width > 0 && area.height > 0;
    }

    static String areaSublabel(CaptureArea area) {
        String region = region(area.getBounds());
        String display = area.getDisplay();
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