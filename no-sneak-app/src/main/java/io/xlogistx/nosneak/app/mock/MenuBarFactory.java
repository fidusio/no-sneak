package io.xlogistx.nosneak.app.mock;


import io.xlogistx.nosneak.app.mock.utility.AppContext;
import io.xlogistx.nosneak.app.mock.utility.Navigator;

import javax.swing.*;

public class MenuBarFactory {

    public JMenuBar buildMenu(AppContext ctx) {
        JMenuBar menuBar = new JMenuBar();

        // JMenuBar -> JMenu -> JMenuItem

        // create menu bar items
        JMenu file = new JMenu("File");
        JMenu view = new JMenu("View");
        JMenu tools = new JMenu("Tools");
        JMenu help = new JMenu("Help");
        JMenu logout = new JMenu("Logout");
        JMenu mode = new JMenu("Mode");

        // create menu bar item
        JMenuItem menuItem = new JMenuItem("Test");
        menuItem.addActionListener(e -> System.out.println("test"));

        JMenuItem confirmLogout = new JMenuItem("Confirm Logout");
        confirmLogout.addActionListener(e -> ctx.session().logout());

        JCheckBoxMenuItem modeToggle = new JCheckBoxMenuItem("Technical Mode");

        JMenuItem scanner = new JMenuItem("Network scanner");
        scanner.addActionListener(e -> ctx.nav().show(Navigator.Screen.SCAN));
        JMenuItem pqc = new JMenuItem("PQC file sharing");
        pqc.addActionListener(e -> ctx.nav().show(Navigator.Screen.MAIN));
        JMenuItem subject = new JMenuItem("Subject Profile");
        subject.addActionListener(e -> ctx.nav().show(Navigator.Screen.SUBJECT));
        JMenuItem manager = new JMenuItem("Subject Security Manager");
        manager.addActionListener(e -> ctx.nav().show(Navigator.Screen.MANAGER));
        JMenuItem aiChat = new JMenuItem("AI Chat");
        aiChat.addActionListener(_ -> ctx.nav().show(Navigator.Screen.INTERFACE));

        view.add(scanner);
        view.add(pqc);
        view.add(subject);
        view.add(manager);
        view.add(aiChat);

        file.add(menuItem);
        mode.add(modeToggle);

        logout.add(confirmLogout);

        // add menu bar items to menu bar
        menuBar.add(file);
        menuBar.add(view);
        menuBar.add(tools);
        menuBar.add(help);
        menuBar.add(Box.createHorizontalGlue());
        menuBar.add(logout);
        menuBar.add(mode);

        return menuBar;
    }
}
