package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.assistant.CaptureArea;
import io.xlogistx.nosneak.ai.model.AICapture;
import org.junit.jupiter.api.Test;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.*;

public class CaptureSupportTest {

    private static BufferedImage image(int width, int height) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        try {
            g.setPaint(new GradientPaint(0, 0, Color.BLUE, width, height, Color.ORANGE));
            g.fillRect(0, 0, width, height);
        } finally {
            g.dispose();
        }
        return image;
    }

    @Test
    public void toCaptureFillsEveryField() throws Exception {
        AICapture capture = CaptureSupport.toCapture(image(640, 360), "grade panel 11:04", "grade panel");

        assertEquals("grade panel 11:04", capture.getName());
        assertEquals("grade panel", capture.getFromArea());
        assertEquals(640, capture.getWidth());
        assertEquals(360, capture.getHeight());
        assertNotNull(capture.getImage());
        assertEquals(capture.getImage().length, capture.getNumBytes());

        BufferedImage decoded = CaptureSupport.toImage(capture.getImage());
        assertEquals(640, decoded.getWidth());
        assertEquals(360, decoded.getHeight());

        BufferedImage thumb = CaptureSupport.toImage(capture.getThumbnail());
        assertNotNull(thumb);
        assertTrue(Math.max(thumb.getWidth(), thumb.getHeight()) <= CaptureSupport.THUMBNAIL_EDGE);
    }

    @Test
    public void toCaptureOfNullImageIsNull() throws Exception {
        assertNull(CaptureSupport.toCapture(null, "name", "area"));
    }

    @Test
    public void scaleKeepsSmallImagesAndAspectRatio() {
        BufferedImage small = image(100, 80);
        assertSame(small, CaptureSupport.scale(small, 200));

        BufferedImage scaled = CaptureSupport.scale(image(400, 200), 200);
        assertEquals(200, scaled.getWidth());
        assertEquals(100, scaled.getHeight());
    }

    @Test
    public void bytesFormats() {
        assertEquals("0 B", CaptureSupport.bytes(0));
        assertEquals("998 B", CaptureSupport.bytes(998));
        assertEquals("1 KB", CaptureSupport.bytes(1024));
        assertEquals("412 KB", CaptureSupport.bytes(421_888));
        assertEquals("1.0 MB", CaptureSupport.bytes(1024 * 1024));
        assertEquals("1.3 MB", CaptureSupport.bytes(1_363_149));
    }

    @Test
    public void shortTimeUsesTheSystemZone() {
        long now = 1_754_560_000_000L;
        String expected = Instant.ofEpochMilli(now).atZone(ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("HH:mm"));
        assertEquals(expected, CaptureSupport.shortTime(now));
    }

    @Test
    public void regionAndUsable() {
        assertEquals("640x360 at 120,180", CaptureSupport.region(new Rectangle(120, 180, 640, 360)));
        assertEquals("no area", CaptureSupport.region(null));

        assertTrue(CaptureSupport.usable(new Rectangle(0, 0, 1, 1)));
        assertFalse(CaptureSupport.usable(new Rectangle(0, 0, 0, 5)));
        assertFalse(CaptureSupport.usable(null));
    }

    @Test
    public void areaSublabelIncludesDisplayWhenPresent() {
        CaptureArea area = new CaptureArea();
        area.setBounds(new Rectangle(120, 180, 640, 360));
        assertEquals("640x360 at 120,180", CaptureSupport.areaSublabel(area));

        area.setDisplay("Display 1");
        assertEquals("Display 1  ·  640x360 at 120,180", CaptureSupport.areaSublabel(area));
    }
}
