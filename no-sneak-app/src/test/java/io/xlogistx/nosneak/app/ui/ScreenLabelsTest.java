package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.ai.assistant.AssistantPanel;
import io.xlogistx.nosneak.app.ui.scan.ProbeLibraryModel;
import io.xlogistx.nosneak.app.ui.scan.ScanResultView;
import io.xlogistx.nosneak.app.ui.utility.Navigator;
import io.xlogistx.nosneak.nmap.NMapConfig;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * One string names a page everywhere (2026-10-26): the sidebar, the page title and the View menu
 * all read {@code Navigator.Screen.getDisplayName()}, and the assistant's own pages carry the same
 * words on {@code AssistantPanel.Page}. The segmented controls are built from their enums too.
 */
class ScreenLabelsTest {

    @Test
    void everyScreenHasADistinctNonBlankLabel() {
        Set<String> seen = new HashSet<>();
        for (Navigator.Screen s : Navigator.Screen.values()) {
            String label = s.getDisplayName();
            assertNotNull(label, s.name());
            assertFalse(label.isBlank(), s.name());
            assertTrue(seen.add(label), "duplicate label " + label);
        }
    }

    @Test
    void assistantPagesAndTheirScreensShareTheLabel() {
        for (AssistantPanel.Page page : AssistantPanel.Page.values()) {
            Navigator.Screen screen = AppShell.screenFor(page);
            if (page == AssistantPanel.Page.QUEUE) {
                assertNull(screen, "the job queue is not offered in the sidebar");
                continue;
            }
            assertNotNull(screen, page.name());
            assertEquals(page.getDisplayName(), screen.getDisplayName(), page.name());
        }
    }

    @Test
    void everyScreenAndPageExplainsItself() {
        for (Navigator.Screen s : Navigator.Screen.values()) {
            assertNotNull(s.getDescription(), s.name());
            assertFalse(s.getDescription().isBlank(), s.name());
        }
        for (AssistantPanel.Page p : AssistantPanel.Page.values()) {
            assertFalse(p.getDescription().isBlank(), p.name());
            Navigator.Screen screen = AppShell.screenFor(p);
            if (screen != null) assertEquals(screen.getDescription(), p.getDescription(), p.name() + " says the same as its screen");
        }
        for (ProbeLibraryModel.Filter f : ProbeLibraryModel.Filter.values())
            assertFalse(f.getDescription().isBlank(), f.name());
        for (ScanResultView.Tab t : ScanResultView.Tab.values())
            assertFalse(t.getDescription().isBlank(), t.name());
        for (SubjectSecManagerPanel.View v : SubjectSecManagerPanel.View.values())
            assertFalse(v.getDescription().isBlank(), v.name());
        assertTrue(NMapConfig.Timing.T3.getDescription().endsWith("(default)"), NMapConfig.Timing.T3.getDescription());
        assertTrue(NMapConfig.Timing.T0.getDescription().startsWith("1 in flight, 1 per second, 15 s timeout"), NMapConfig.Timing.T0.getDescription());
    }

    @Test
    void segmentEnumsLabelThemselves() {
        assertEquals("All", ProbeLibraryModel.Filter.ALL.getDisplayName());
        assertEquals("Mine", ProbeLibraryModel.Filter.MINE.getDisplayName());
        for (NMapConfig.Timing t : NMapConfig.Timing.values())
            assertEquals(t.name(), t.getDisplayName(), "the -T token is the label");
    }
}
