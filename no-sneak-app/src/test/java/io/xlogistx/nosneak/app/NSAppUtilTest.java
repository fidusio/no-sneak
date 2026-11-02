package io.xlogistx.nosneak.app;

import io.xlogistx.gui.GUIUtil;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetDisplayName;
import org.zoxweb.shared.util.GetName;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pins the UI descriptor rule (2026-11-01): every enum in {@link NSAppUtil} implements the three
 * zoxweb interfaces, every constant has a distinct non-blank name and a non-null display name,
 * and gui-audio's {@code GUIUtil.applyProp} maps name → component name, description → tooltip, display name →
 * text (button, label) or placeholder (text field), leaving a blank display name alone.
 */
class NSAppUtilTest {

    /** Every enum declared in {@code NSAppUtil}: a new panel's enum is covered the moment it is added. */
    private static final Class<?>[] ENUMS = java.util.Arrays.stream(NSAppUtil.class.getDeclaredClasses())
            .filter(Class::isEnum).toArray(Class<?>[]::new);

    @Test
    void everyDescriptorEnumHasDistinctNonBlankNames() {
        assertTrue(ENUMS.length >= 9, "the enums are found by reflection: " + ENUMS.length);
        Set<String> allNames = new HashSet<>();
        for (Class<?> e : ENUMS) {
            assertTrue(GetName.class.isAssignableFrom(e) && GetDescription.class.isAssignableFrom(e)
                    && GetDisplayName.class.isAssignableFrom(e), e.getSimpleName() + " implements the three interfaces");
            Set<String> names = new HashSet<>();
            for (Object c : e.getEnumConstants()) {
                String name = ((GetName) c).getName();
                assertNotNull(name, c.toString());
                assertFalse(name.isBlank(), c.toString());
                assertTrue(names.add(name), e.getSimpleName() + " duplicates the name " + name);
                assertTrue(allNames.add(name), "the name " + name + " is used by two enums");
                assertNotNull(((GetDisplayName) c).getDisplayName(), c + " has no display name");
            }
        }
    }

    @Test
    void applyMapsNameTooltipAndText() {
        JButton b = GUIUtil.applyProp(new JButton(), NSAppUtil.ProbeGroupsPage.NEW_GROUP);
        assertEquals("probeGroups.new", b.getName());
        assertEquals("New group", b.getText());
        assertEquals(NSAppUtil.ProbeGroupsPage.NEW_GROUP.getDescription(), b.getToolTipText());

        JLabel l = GUIUtil.applyProp(new JLabel("before"), NSAppUtil.ProbeGroupsPage.COUNT);
        assertEquals("probeGroups.count", l.getName());
        assertEquals("before", l.getText(), "a blank display name leaves the text alone (filled at run time)");
        assertEquals(NSAppUtil.ProbeGroupsPage.COUNT.getDescription(), l.getToolTipText());

        JTextField f = GUIUtil.applyProp(new JTextField(), NSAppUtil.ProbeGroupEditor.SEARCH);
        assertEquals("", f.getText(), "the display name of a field is its placeholder, not its text");
        assertEquals("Search probes", f.getClientProperty("JTextField.placeholderText"));

        JPanel p = GUIUtil.applyProp(new JPanel(), NSAppUtil.ProbeGroupsPage.TITLE);
        assertEquals("probeGroups.title", p.getName());
        assertNull(p.getToolTipText(), "no description, no tooltip");
    }

    @Test
    void theColumnsAreTheEnumInOrder() {
        NSAppUtil.ProbeGroupColumn[] cols = NSAppUtil.ProbeGroupColumn.values();
        assertEquals("Name", cols[0].getDisplayName());
        assertEquals("Probes", cols[1].getDisplayName());
        assertEquals("Description", cols[2].getDisplayName());
    }
}
