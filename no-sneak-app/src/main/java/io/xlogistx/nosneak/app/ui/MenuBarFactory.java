package io.xlogistx.nosneak.app.ui;


import io.xlogistx.nosneak.app.ui.utility.AppContext;
import io.xlogistx.nosneak.app.ui.utility.Navigator;

import javax.swing.*;

public class MenuBarFactory {

    public JMenuBar buildMenu(AppContext ctx) {
        JMenuBar menuBar = new JMenuBar();

        // JMenuBar -> JMenu -> JMenuItem

        // create menu bar items
        JMenu file = new JMenu("File");
        JMenu tools = new JMenu("Tools");
        JMenu help = new JMenu("Help");
        JMenu mode = new JMenu("Mode");

        JMenuItem logout = new JMenuItem("Logout");
        logout.setMaximumSize(logout.getPreferredSize());
        logout.addActionListener(_ -> {
            int ok = JOptionPane.showConfirmDialog(menuBar, "Log out of NoSneak?", "Logout",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
            if (ok == JOptionPane.OK_OPTION) ctx.session().logout();
        });

        JCheckBoxMenuItem modeToggle = new JCheckBoxMenuItem("Technical Mode");

        JMenuItem scanner = new JMenuItem("Network scanner");
        scanner.addActionListener(e -> ctx.nav().show(Navigator.Screen.SCAN));

//      JMenuItem pqc = new JMenuItem("PQC file sharing");
//      pqc.addActionListener(e -> ctx.nav().show(Navigator.Screen.MAIN));

        JMenuItem settings = new JMenuItem("Settings");
        settings.addActionListener(e -> ctx.nav().show(Navigator.Screen.SUBJECT));

        JMenuItem manager = new JMenuItem("ACL Tool");
        manager.addActionListener(e -> ctx.nav().show(Navigator.Screen.MANAGER));

        JMenuItem aiChat = new JMenuItem("AI Assistant");
        aiChat.addActionListener(_ -> ctx.nav().show(Navigator.Screen.ASSISTANT));

        JMenuItem appInfo = new JMenuItem("App Info");
        appInfo.addActionListener(_ -> ctx.nav().show(Navigator.Screen.INFO));

        // FILE
        file.add(settings);

        // TOOLS
        tools.add(scanner);
        tools.add(manager);
        tools.add(aiChat);
//        tools.add(pqc);

        // HELP
        help.add(appInfo);


        mode.add(modeToggle);

        // add menu bar items to menu bar
        menuBar.add(file);
        menuBar.add(tools);
        menuBar.add(help);
        menuBar.add(Box.createHorizontalGlue());
        menuBar.add(logout);
        menuBar.add(mode);

        return menuBar;
    }
}
