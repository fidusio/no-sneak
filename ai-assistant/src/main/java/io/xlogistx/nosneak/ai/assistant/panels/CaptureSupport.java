package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.gui.GUIUtil;
import io.xlogistx.nosneak.ai.model.AICapture;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public final class CaptureSupport {

    static final String IMAGE_FORMAT = "png";
    static final int THUMBNAIL_EDGE = 200;

    private static final int SETTLE_MILLIS = 150;

    private CaptureSupport() {
    }

    static Rectangle select(Window owner) throws Exception {
        hideWindow(owner);
        try {
            Rectangle area = drag();
            return usable(area) ? area : null;
        } finally {
            restoreWindow(owner);
        }
    }

    static BufferedImage shoot(Window owner, Rectangle preset) throws Exception {
        hideWindow(owner);
        try {
            Rectangle area = (preset != null) ? preset : drag();
            if (!usable(area)) return null;
            return GUIUtil.captureSelectedArea(area);
        } finally {
            restoreWindow(owner);
        }
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

    private static Rectangle drag() throws Exception {
        Rectangle area = GUIUtil.captureSelectedArea();
        settle();
        return area;
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