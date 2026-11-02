package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.gui.GUIUtil;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetDisplayName;
import org.zoxweb.shared.util.GetName;

import javax.swing.JButton;
import javax.swing.JLabel;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pins the UI descriptor rule for the assistant module (2026-11-01, the twin of the app's
 * {@code NSAppUtilTest}): every enum in {@link AIAssistantUtil} implements the three zoxweb
 * interfaces, every constant has a distinct non-blank name and a non-null display name across
 * all enums, and gui-audio's {@code GUIUtil.applyProp} maps name → component name, description →
 * tooltip, display name → text. The enums are found by reflection, so a new one is covered the
 * moment it is declared.
 */
class AIAssistantUtilTest {

    private static final Class<?>[] ENUMS = Arrays.stream(AIAssistantUtil.class.getDeclaredClasses())
            .filter(Class::isEnum).toArray(Class<?>[]::new);

    @Test
    void everyDescriptorEnumHasDistinctNonBlankNames() {
        assertTrue(ENUMS.length >= 1, "the enums are found by reflection: " + ENUMS.length);
        Set<String> allNames = new HashSet<>();
        for (Class<?> e : ENUMS) {
            assertTrue(GetName.class.isAssignableFrom(e) && GetDescription.class.isAssignableFrom(e)
                    && GetDisplayName.class.isAssignableFrom(e), e.getSimpleName() + " implements the three interfaces");
            for (Object c : e.getEnumConstants()) {
                String name = ((GetName) c).getName();
                assertNotNull(name, c.toString());
                assertFalse(name.isBlank(), c.toString());
                assertTrue(allNames.add(name), "the name " + name + " is used twice");
                assertNotNull(((GetDisplayName) c).getDisplayName(), c + " has no display name");
            }
        }
    }

    @Test
    void applyMapsNameTooltipAndText() {
        JButton b = GUIUtil.applyProp(new JButton(), AIAssistantUtil.Page.CHAT);
        assertEquals("assistant.page.chat", b.getName());
        assertEquals("Chat", b.getText());
        assertEquals(AIAssistantUtil.Page.CHAT.getDescription(), b.getToolTipText());

        JLabel l = GUIUtil.applyProp(new JLabel(), AIAssistantUtil.Page.QUEUE);
        assertEquals("Job Queue", l.getText());
    }

    @Test
    void thePagesKeepTheirTitles() {
        assertEquals("Chat", AIAssistantUtil.Page.CHAT.getDisplayName());
        assertEquals("Skills", AIAssistantUtil.Page.SKILLS.getDisplayName());
        assertEquals("Providers", AIAssistantUtil.Page.PROVIDERS.getDisplayName());
        assertEquals("Capture", AIAssistantUtil.Page.CAPTURE.getDisplayName());
        for (AIAssistantUtil.Page p : AIAssistantUtil.Page.values()) assertFalse(p.getDescription().isBlank(), p.name());
    }
}
