package io.xlogistx.nosneak.app.mock;

import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.nosneak.app.mock.utility.DataStoreConfig;

import javax.swing.*;
import java.io.IOException;
import java.util.Properties;

public class DataStoreSetupPanel extends JPanel {
    private final JTextField fileSystemButton = PanelBuilder.textField("");
    private final JTextField dbUserButton = PanelBuilder.textField("");
    private final JTextField dbPasswordButton = PanelBuilder.textField("");
    private final JTextField dbEncryptionPasswordButton = PanelBuilder.textField("");
    private final JButton saveButton = new JButton("Save");
    private final Runnable onComplete;

    public DataStoreSetupPanel(Runnable onComplete) {
        this.onComplete = onComplete;

        JLabel title = PanelBuilder.title("Data Store Setup");
        JLabel fileSystem = new JLabel("File System");
        JLabel dbUser = new JLabel("Database Username");
        JLabel dbPassword = new JLabel("Database Password");
        JLabel dbEncryptionPassword = new JLabel("Encryption Password");

        saveButton.addActionListener(e -> save());


        add(PanelBuilder.buildJPanelWithFields(
                title,
                fileSystem, fileSystemButton,
                dbUser, dbUserButton,
                dbPassword, dbPasswordButton,
                dbEncryptionPassword, dbEncryptionPasswordButton,
                saveButton
        ));
    }

    private void save() {
        /*
        Properties p = new Properties();
        p.setProperty(DataStoreConfig.Key.PATH, fileSystemButton.getText().trim());
        p.setProperty(DataStoreConfig.Key.USER, dbUserButton.getText().trim());
        p.setProperty(DataStoreConfig.Key.PASSWORD, dbPasswordButton.getText().trim());

        try {
            DataStoreConfig.save(p);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage());
        }
         */
        onComplete.run();
    }
}
