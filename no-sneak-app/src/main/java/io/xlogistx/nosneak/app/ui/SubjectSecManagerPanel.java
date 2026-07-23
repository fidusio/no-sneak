package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.PanelBuilder;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

public class SubjectSecManagerPanel extends JPanel {
    private final CardStack cardStack = new CardStack();

    SubjectSecManagerPanel(AppContext ctx) {
        setLayout(new BorderLayout());

        cardStack.add(buildSubjectPanel(), "Subjects");
        cardStack.add(buildPermissionsPanel(), "Permissions");
        cardStack.add(buildRolesPanel(), "Roles");
        cardStack.add(buildRoleGroupsPanel(), "RoleGroups");
        cardStack.add(buildGrantsPanel(), "Grants");
        cardStack.show("Subjects");

        JToggleButton subjectButton = new JToggleButton("Subjects");
        subjectButton.addActionListener(e -> cardStack.show("Subjects"));
        JToggleButton permissionButton = new JToggleButton("Permissions");
        permissionButton.addActionListener(e -> cardStack.show("Permissions"));
        JToggleButton roleButton = new JToggleButton("Roles");
        roleButton.addActionListener(e -> cardStack.show("Roles"));
        JToggleButton roleGroupButton = new JToggleButton("RoleGroups");
        roleGroupButton.addActionListener(e -> cardStack.show("RoleGroups"));
        JToggleButton grantButton = new JToggleButton("Grants");
        grantButton.addActionListener(e -> cardStack.show("Grants"));

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), subjectButton, permissionButton, roleButton, roleGroupButton, grantButton));
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