package io.xlogistx.nosneak.ai.assistant.panels;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

final class RegionOverlay {

    record Selection(Rectangle bounds, String display, int displayIndex) {
    }

    private static final Color DIM = new Color(0, 0, 0, 50);
    private static final Color FILL = new Color(255, 255, 255, 30);
    private static final Color OUTLINE = Color.RED;

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition finished = lock.newCondition();
    private final List<JWindow> windows = new ArrayList<>();
    private final List<Rectangle> screens = new ArrayList<>();

    private Point dragStart;
    private Rectangle rubberBand;
    private int pressIndex;
    private boolean done;
    private boolean cancelled;
    private Rectangle result;
    private int resultIndex;

    private RegionOverlay() {
    }

    static Selection select() throws Exception {
        if (SwingUtilities.isEventDispatchThread())
            throw new IllegalStateException("RegionOverlay.select() cannot run on the EDT");
        return new RegionOverlay().run();
    }

    private Selection run() throws Exception {
        KeyEventDispatcher escape = this::onKey;
        try {
            SwingUtilities.invokeAndWait(() -> show(escape));
            lock.lock();
            try {
                while (!done) finished.await();
                if (cancelled || result == null) return null;
                return new Selection(result, "Display " + (resultIndex + 1), resultIndex);
            } finally {
                lock.unlock();
            }
        } finally {
            SwingUtilities.invokeLater(() -> dismiss(escape));
        }
    }

    private void show(KeyEventDispatcher escape) {
        GraphicsDevice[] devices = GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices();
        for (int i = 0; i < devices.length; i++) {
            GraphicsConfiguration config = devices[i].getDefaultConfiguration();
            Rectangle bounds = config.getBounds();
            screens.add(bounds);

            JWindow window = new JWindow(config);
            window.setAlwaysOnTop(true);
            window.setFocusableWindowState(true);
            dim(devices[i], window);
            window.setBounds(bounds);
            window.setContentPane(glass(window, i));
            window.setVisible(true);
            windows.add(window);
        }
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(escape);
        focusPointerWindow(devices);
    }

    private static void dim(GraphicsDevice device, JWindow window) {
        try {
            if (device.isWindowTranslucencySupported(GraphicsDevice.WindowTranslucency.PERPIXEL_TRANSLUCENT)) {
                window.setBackground(DIM);
            } else if (device.isWindowTranslucencySupported(GraphicsDevice.WindowTranslucency.TRANSLUCENT)) {
                window.setBackground(Color.BLACK);
                window.setOpacity(0.35f);
            } else {
                window.setBackground(new Color(30, 30, 30));
            }
        } catch (UnsupportedOperationException e) {
            window.setBackground(new Color(30, 30, 30));
        }
    }

    private JComponent glass(JWindow window, int index) {
        JComponent glass = new JComponent() {
            @Override
            protected void paintComponent(Graphics g) {
                Rectangle band = rubberBand;
                if (band == null) return;
                Rectangle local = new Rectangle(band);
                local.translate(-window.getX(), -window.getY());
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setColor(FILL);
                g2.fill(local);
                g2.setColor(OUTLINE);
                g2.draw(local);
                g2.dispose();
            }
        };
        glass.setOpaque(false);
        glass.setCursor(Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR));
        glass.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                pressIndex = index;
                dragStart = new Point(e.getX() + window.getX(), e.getY() + window.getY());
                rubberBand = new Rectangle(dragStart);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                finish(false);
            }
        });
        glass.addMouseMotionListener(new MouseMotionAdapter() {
            @Override
            public void mouseDragged(MouseEvent e) {
                if (dragStart == null) return;
                Point current = new Point(e.getX() + window.getX(), e.getY() + window.getY());
                rubberBand = normalize(dragStart, current);
                for (JWindow w : windows) w.repaint();
            }
        });
        return glass;
    }

    private void focusPointerWindow(GraphicsDevice[] devices) {
        PointerInfo pointer = MouseInfo.getPointerInfo();
        JWindow target = windows.isEmpty() ? null : windows.get(0);
        if (pointer != null) {
            for (int i = 0; i < devices.length; i++) {
                if (devices[i] == pointer.getDevice() && i < windows.size()) {
                    target = windows.get(i);
                    break;
                }
            }
        }
        if (target != null) target.requestFocus();
    }

    private boolean onKey(KeyEvent e) {
        if (e.getID() == KeyEvent.KEY_PRESSED && e.getKeyCode() == KeyEvent.VK_ESCAPE) {
            e.consume();
            finish(true);
            return true;
        }
        return false;
    }

    private void finish(boolean cancel) {
        lock.lock();
        try {
            if (done) return;
            if (!cancel && rubberBand != null) {
                Rectangle clamped = clamp(rubberBand);
                if (clamped.width > 0 && clamped.height > 0) {
                    result = clamped;
                    resultIndex = attributeDisplay(clamped);
                }
            }
            cancelled = cancel;
            done = true;
            finished.signalAll();
        } finally {
            lock.unlock();
        }
    }

    private void dismiss(KeyEventDispatcher escape) {
        KeyboardFocusManager.getCurrentKeyboardFocusManager().removeKeyEventDispatcher(escape);
        for (JWindow window : windows) window.dispose();
        windows.clear();
    }

    private static Rectangle normalize(Point a, Point b) {
        int x = Math.min(a.x, b.x);
        int y = Math.min(a.y, b.y);
        return new Rectangle(x, y, Math.abs(a.x - b.x), Math.abs(a.y - b.y));
    }

    private Rectangle clamp(Rectangle rect) {
        Rectangle union = null;
        for (Rectangle screen : screens)
            union = (union == null) ? new Rectangle(screen) : union.union(screen);
        return (union == null) ? rect : rect.intersection(union);
    }

    private int attributeDisplay(Rectangle rect) {
        int best = pressIndex;
        long bestArea = 0;
        for (int i = 0; i < screens.size(); i++) {
            Rectangle overlap = screens.get(i).intersection(rect);
            long area = overlap.isEmpty() ? 0 : (long) overlap.width * overlap.height;
            if (area > bestArea) {
                bestArea = area;
                best = i;
            }
        }
        return best;
    }
}
