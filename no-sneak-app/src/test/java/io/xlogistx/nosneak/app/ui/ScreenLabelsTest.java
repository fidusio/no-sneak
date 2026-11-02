package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.ai.assistant.AIAssistantUtil;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.nmap.NMapConfig;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * One string names a page everywhere (2026-10-26): the sidebar, the page title and the View menu
 * all read {@code NSAppUtil.Screen.getDisplayName()}, and the assistant's own pages carry the same
 * words on {@code AIAssistantUtil.Page}. The segmented controls are built from their enums too.
 */
class ScreenLabelsTest {

    @Test
    void everyScreenHasADistinctNonBlankLabel() {
        Set<String> seen = new HashSet<>();
        for (NSAppUtil.Screen s : NSAppUtil.Screen.values()) {
            String label = s.getDisplayName();
            assertNotNull(label, s.name());
            assertFalse(label.isBlank(), s.name());
            assertTrue(seen.add(label), "duplicate label " + label);
        }
    }

    @Test
    void assistantPagesAndTheirScreensShareTheLabel() {
        for (AIAssistantUtil.Page page : AIAssistantUtil.Page.values()) {
            NSAppUtil.Screen screen = AppShell.screenFor(page);
            if (page == AIAssistantUtil.Page.QUEUE) {
                assertNull(screen, "the job queue is not offered in the sidebar");
                continue;
            }
            assertNotNull(screen, page.name());
            assertEquals(page.getDisplayName(), screen.getDisplayName(), page.name());
        }
    }

    @Test
    void everyScreenAndPageExplainsItself() {
        for (NSAppUtil.Screen s : NSAppUtil.Screen.values()) {
            assertNotNull(s.getDescription(), s.name());
            assertFalse(s.getDescription().isBlank(), s.name());
        }
        for (AIAssistantUtil.Page p : AIAssistantUtil.Page.values()) {
            assertFalse(p.getDescription().isBlank(), p.name());
            NSAppUtil.Screen screen = AppShell.screenFor(p);
            if (screen != null) assertEquals(screen.getDescription(), p.getDescription(), p.name() + " says the same as its screen");
        }
        for (NSAppUtil.ProbeLibraryFilter f : NSAppUtil.ProbeLibraryFilter.values())
            assertFalse(f.getDescription().isBlank(), f.name());
        for (NSAppUtil.ScanResultTab t : NSAppUtil.ScanResultTab.values())
            assertFalse(t.getDescription().isBlank(), t.name());
        for (NSAppUtil.AclView v : NSAppUtil.AclView.values())
            assertFalse(v.getDescription().isBlank(), v.name());
        assertTrue(NMapConfig.Timing.T3.getDescription().endsWith("(default)"), NMapConfig.Timing.T3.getDescription());
        assertTrue(NMapConfig.Timing.T0.getDescription().startsWith("1 in flight, 1 per second, 15 s timeout"), NMapConfig.Timing.T0.getDescription());
    }

    @Test
    void segmentEnumsLabelThemselves() {
        assertEquals("All", NSAppUtil.ProbeLibraryFilter.ALL.getDisplayName());
        assertEquals("Mine", NSAppUtil.ProbeLibraryFilter.MINE.getDisplayName());
        for (NMapConfig.Timing t : NMapConfig.Timing.values())
            assertEquals(t.name(), t.getDisplayName(), "the -T token is the label");
    }
}
