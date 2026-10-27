package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.PagePanel;
import io.xlogistx.gui.UITokens;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.ComponentRef;
import io.xlogistx.gui.PanelBuilder;
import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetDisplayName;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.EnumMap;
import java.util.Map;

public class SubjectSecManagerPanel extends JPanel {
    private final CardStack cardStack = new CardStack();

    /** The page's five views (2026-10-27): the display name is the tab's title, the description its tooltip. */
    public enum View implements GetDisplayName, GetDescription {
        SUBJECTS("Subjects", "Security subjects and their principals, credentials and grants"),
        PERMISSIONS("Permissions", "Permission definitions, scoped by application"),
        ROLES("Roles", "Named bundles of permissions"),
        ROLE_GROUPS("Role groups", "Bundles of roles granted together"),
        GRANTS("Grants", "Permission, role and role-group grants bound to subjects");

        private final String displayName;
        private final String description;

        View(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }

        @Override
        public String getDisplayName() {
            return displayName;
        }

        @Override
        public String getDescription() {
            return description;
        }
    }

    /** One ref per view: the tab's content is the component, the constant the source. */
    private final Map<View, ComponentRef<View>> views = new EnumMap<>(View.class);

    /** The view's ref: its content as the component, its title and tooltip the constant's. */
    public ComponentRef<View> view(View v) {
        return views.get(v);
    }

    private void tab(JTabbedPane tabs, View v, JComponent content) {
        ComponentRef<View> ref = new ComponentRef<>(content, v);
        views.put(v, ref);
        tabs.addTab(ref.getDisplayName(), null, content, ref.getDescription());
    }

    SubjectSecManagerPanel(AppContext ctx) {
        setLayout(new BorderLayout());

        // one sidebar item (Access control) opens this page; its five views are tabs (2026-10-24)
        JTabbedPane tabs = new JTabbedPane();
        tab(tabs, View.SUBJECTS, buildSubjectPanel());
        tab(tabs, View.PERMISSIONS, buildPermissionsPanel());
        tab(tabs, View.ROLES, buildRolesPanel());
        tab(tabs, View.ROLE_GROUPS, buildRoleGroupsPanel());
        tab(tabs, View.GRANTS, buildGrantsPanel());
        tabs.setBorder(BorderFactory.createEmptyBorder(8, 12, 12, 12));
        tabs.setBackground(UITokens.surface());
        PagePanel page = new PagePanel(Navigator.Screen.ACL.getDisplayName(),
                "Every subject in this store, with its permissions, roles, role groups and grants. Super-admin only.");
        page.card(tabs);
        add(page, BorderLayout.CENTER);
    }

    private JPanel buildSubjectPanel() {
        JTextField search = new JTextField(20);
        JButton searchButton = GUIUtil.iconButton(new IconUtil.SearchIcon(16));
        searchButton.setToolTipText("Search");
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(search);
        searchBar.add(searchButton);

        return PanelBuilder.buildJPanelWithFields(
                new JLabel("Subjects"),
                new JLabel("Security subjects and their principals, credentials, and grants."),
                searchBar,
                new JScrollPane(new JTable(new DefaultTableModel(
                        new String[]{"Name", "Primary principal", "Owns", ""}, 5
                )))

        );
    }

    private JPanel buildPermissionsPanel() {
        JTextField search = new JTextField(20);
        JButton searchButton = GUIUtil.iconButton(new IconUtil.SearchIcon(16));
        searchButton.setToolTipText("Search");
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(search);
        searchBar.add(searchButton);

        return PanelBuilder.buildJPanelWithFields(
                new JLabel("Permissions"),
                new JLabel("Permission definitions, scoped by application (AppID)."),
                searchBar,
                new JScrollPane(new JTable(new DefaultTableModel(
                        new String[]{"Permission", "Description", ""}, 5
                )))
        );
    }

    private JPanel buildRolesPanel() {
        JTextField search = new JTextField(20);
        JButton searchButton = GUIUtil.iconButton(new IconUtil.SearchIcon(16));
        searchButton.setToolTipText("Search");
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(search);
        searchBar.add(searchButton);

        return PanelBuilder.buildJPanelWithFields(
                new JLabel("Roles"),
                new JLabel("Named bundles of permissions."),
                searchBar,
                new JScrollPane(new JTable(new DefaultTableModel(
                        new String[]{"Role", "Description", ""}, 5
                )))
        );
    }

    private JPanel buildRoleGroupsPanel() {
        JTextField search = new JTextField(20);
        JButton searchButton = GUIUtil.iconButton(new IconUtil.SearchIcon(16));
        searchButton.setToolTipText("Search");
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(search);
        searchBar.add(searchButton);

        return PanelBuilder.buildJPanelWithFields(
                new JLabel("Role groups"),
                new JLabel("Bundles of roles granted together."),
                searchBar,
                new JScrollPane(new JTable(new DefaultTableModel(
                        new String[]{"Role Group", "Roles", ""}, 5
                )))
        );
    }

    private JPanel buildGrantsPanel() {
        JTextField search = new JTextField(20);
        JButton searchButton = GUIUtil.iconButton(new IconUtil.SearchIcon(16));
        searchButton.setToolTipText("Search");
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(search);
        searchBar.add(searchButton);

        return PanelBuilder.buildJPanelWithFields(
                new JLabel("Grants"),
                new JLabel("Permission, role, and role-group grants bound to subjects."),
                searchBar,
                new JScrollPane(new JTable(new DefaultTableModel(
                        new String[]{"Subject", "Grant Type", "Granted", ""}, 5
                )))
        );
    }
}