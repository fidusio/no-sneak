package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.PagePanel;
import io.xlogistx.gui.UITokens;
import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.gui.CardStack;
import io.xlogistx.gui.ComponentRef;
import io.xlogistx.gui.PanelBuilder;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.EnumMap;
import java.util.Map;

public class SubjectSecManagerPanel extends JPanel {
    private final CardStack cardStack = new CardStack();

    /** One ref per view: the tab's content is the component, the constant the source. */
    private final Map<NSAppUtil.AclView, ComponentRef<NSAppUtil.AclView>> views = new EnumMap<>(NSAppUtil.AclView.class);

    /** The view's ref: its content as the component, its title and tooltip the constant's. */
    public ComponentRef<NSAppUtil.AclView> view(NSAppUtil.AclView v) {
        return views.get(v);
    }

    private void tab(JTabbedPane tabs, NSAppUtil.AclView v, JComponent content) {
        ComponentRef<NSAppUtil.AclView> ref = new ComponentRef<>(content, v);
        views.put(v, ref);
        tabs.addTab(ref.getDisplayName(), null, content, ref.getDescription());
    }

    SubjectSecManagerPanel(AppContext ctx) {
        setLayout(new BorderLayout());
        setName(NSAppUtil.AclPage.PAGE.getName());

        // one sidebar item (Access control) opens this page; its five views are tabs (2026-10-24)
        JTabbedPane tabs = GUIUtil.applyProp(new JTabbedPane(), NSAppUtil.AclPage.TABS);
        tab(tabs, NSAppUtil.AclView.SUBJECTS, buildSubjectPanel());
        tab(tabs, NSAppUtil.AclView.PERMISSIONS, buildPermissionsPanel());
        tab(tabs, NSAppUtil.AclView.ROLES, buildRolesPanel());
        tab(tabs, NSAppUtil.AclView.ROLE_GROUPS, buildRoleGroupsPanel());
        tab(tabs, NSAppUtil.AclView.GRANTS, buildGrantsPanel());
        tabs.setBorder(BorderFactory.createEmptyBorder(8, 12, 12, 12));
        tabs.setBackground(UITokens.surface());
        PagePanel page = new PagePanel(NSAppUtil.Screen.ACL.getDisplayName(), NSAppUtil.AclPage.PAGE.getDescription());
        page.card(tabs);
        add(page, BorderLayout.CENTER);
    }

    /** The table headers of a view: the constants' display names, in order (the last one is blank, the actions column). */
    private static String[] headers(NSAppUtil.AclPage... columns) {
        String[] out = new String[columns.length];
        for (int i = 0; i < columns.length; i++) out[i] = columns[i].getDisplayName();
        return out;
    }

    private JPanel buildSubjectPanel() {
        JTextField search = GUIUtil.applyProp(new JTextField(20), NSAppUtil.AclPage.SUBJECTS_SEARCH_FIELD);
        JButton searchButton = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.SearchIcon(16)), NSAppUtil.AclPage.SUBJECTS_SEARCH);
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(search);
        searchBar.add(searchButton);

        return PanelBuilder.buildJPanelWithFields(
                GUIUtil.applyProp(new JLabel(), NSAppUtil.AclView.SUBJECTS),
                GUIUtil.applyProp(new JLabel(NSAppUtil.AclView.SUBJECTS.getDescription()), NSAppUtil.AclPage.SUBJECTS_SUBTITLE),
                searchBar,
                new JScrollPane(GUIUtil.applyProp(new JTable(new DefaultTableModel(
                        headers(NSAppUtil.AclPage.SUBJECTS_COL_NAME, NSAppUtil.AclPage.SUBJECTS_COL_PRINCIPAL, NSAppUtil.AclPage.SUBJECTS_COL_OWNS, NSAppUtil.AclPage.SUBJECTS_COL_ACTIONS), 5
                )), NSAppUtil.AclPage.SUBJECTS_TABLE))

        );
    }

    private JPanel buildPermissionsPanel() {
        JTextField search = GUIUtil.applyProp(new JTextField(20), NSAppUtil.AclPage.PERMISSIONS_SEARCH_FIELD);
        JButton searchButton = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.SearchIcon(16)), NSAppUtil.AclPage.PERMISSIONS_SEARCH);
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(search);
        searchBar.add(searchButton);

        return PanelBuilder.buildJPanelWithFields(
                GUIUtil.applyProp(new JLabel(), NSAppUtil.AclView.PERMISSIONS),
                GUIUtil.applyProp(new JLabel(NSAppUtil.AclView.PERMISSIONS.getDescription()), NSAppUtil.AclPage.PERMISSIONS_SUBTITLE),
                searchBar,
                new JScrollPane(GUIUtil.applyProp(new JTable(new DefaultTableModel(
                        headers(NSAppUtil.AclPage.PERMISSIONS_COL_PERMISSION, NSAppUtil.AclPage.PERMISSIONS_COL_DESCRIPTION, NSAppUtil.AclPage.PERMISSIONS_COL_ACTIONS), 5
                )), NSAppUtil.AclPage.PERMISSIONS_TABLE))
        );
    }

    private JPanel buildRolesPanel() {
        JTextField search = GUIUtil.applyProp(new JTextField(20), NSAppUtil.AclPage.ROLES_SEARCH_FIELD);
        JButton searchButton = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.SearchIcon(16)), NSAppUtil.AclPage.ROLES_SEARCH);
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(search);
        searchBar.add(searchButton);

        return PanelBuilder.buildJPanelWithFields(
                GUIUtil.applyProp(new JLabel(), NSAppUtil.AclView.ROLES),
                GUIUtil.applyProp(new JLabel(NSAppUtil.AclView.ROLES.getDescription()), NSAppUtil.AclPage.ROLES_SUBTITLE),
                searchBar,
                new JScrollPane(GUIUtil.applyProp(new JTable(new DefaultTableModel(
                        headers(NSAppUtil.AclPage.ROLES_COL_ROLE, NSAppUtil.AclPage.ROLES_COL_DESCRIPTION, NSAppUtil.AclPage.ROLES_COL_ACTIONS), 5
                )), NSAppUtil.AclPage.ROLES_TABLE))
        );
    }

    private JPanel buildRoleGroupsPanel() {
        JTextField search = GUIUtil.applyProp(new JTextField(20), NSAppUtil.AclPage.ROLE_GROUPS_SEARCH_FIELD);
        JButton searchButton = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.SearchIcon(16)), NSAppUtil.AclPage.ROLE_GROUPS_SEARCH);
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(search);
        searchBar.add(searchButton);

        return PanelBuilder.buildJPanelWithFields(
                GUIUtil.applyProp(new JLabel(), NSAppUtil.AclView.ROLE_GROUPS),
                GUIUtil.applyProp(new JLabel(NSAppUtil.AclView.ROLE_GROUPS.getDescription()), NSAppUtil.AclPage.ROLE_GROUPS_SUBTITLE),
                searchBar,
                new JScrollPane(GUIUtil.applyProp(new JTable(new DefaultTableModel(
                        headers(NSAppUtil.AclPage.ROLE_GROUPS_COL_GROUP, NSAppUtil.AclPage.ROLE_GROUPS_COL_ROLES, NSAppUtil.AclPage.ROLE_GROUPS_COL_ACTIONS), 5
                )), NSAppUtil.AclPage.ROLE_GROUPS_TABLE))
        );
    }

    private JPanel buildGrantsPanel() {
        JTextField search = GUIUtil.applyProp(new JTextField(20), NSAppUtil.AclPage.GRANTS_SEARCH_FIELD);
        JButton searchButton = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.SearchIcon(16)), NSAppUtil.AclPage.GRANTS_SEARCH);
        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchBar.add(search);
        searchBar.add(searchButton);

        return PanelBuilder.buildJPanelWithFields(
                GUIUtil.applyProp(new JLabel(), NSAppUtil.AclView.GRANTS),
                GUIUtil.applyProp(new JLabel(NSAppUtil.AclView.GRANTS.getDescription()), NSAppUtil.AclPage.GRANTS_SUBTITLE),
                searchBar,
                new JScrollPane(GUIUtil.applyProp(new JTable(new DefaultTableModel(
                        headers(NSAppUtil.AclPage.GRANTS_COL_SUBJECT, NSAppUtil.AclPage.GRANTS_COL_TYPE, NSAppUtil.AclPage.GRANTS_COL_GRANTED, NSAppUtil.AclPage.GRANTS_COL_ACTIONS), 5
                )), NSAppUtil.AclPage.GRANTS_TABLE))
        );
    }
}