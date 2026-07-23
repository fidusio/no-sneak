package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.PanelBuilder;
import org.zoxweb.shared.security.DomainSecurityManager;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.function.Consumer;

public class DataStoreSetupPanel extends JPanel {

    /**
     * Builds (creates or opens) the data store from the collected setup fields and returns
     * the resulting {@link DomainSecurityManager}. Runs off the EDT, so it may block and throw.
     */
    @FunctionalInterface
    public interface DataStoreFactory {
        DomainSecurityManager create(String location, String user, String password, String encPassword) throws Exception;
    }

    private String path;
    private final JTextField dbUserText = PanelBuilder.textField("", 20);
    private final JPasswordField dbPasswordText = new JPasswordField(20);
    private final JPasswordField dbEncryptionPasswordText = new JPasswordField(20);
    private final JButton createButton = new JButton("Create/Login");
    private final DataStoreFactory factory;
    private final Consumer<DomainSecurityManager> onComplete;

    public DataStoreSetupPanel(DataStoreFactory factory, Consumer<DomainSecurityManager> onComplete) {
        this.factory = factory;
        this.onComplete = onComplete;

        setLayout(new BorderLayout());

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose Location");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setCurrentDirectory(new File(System.getProperty("user.home")));

        JLabel title = PanelBuilder.title("Data Store Setup");
        JLabel description = new JLabel("Configure your database location and credentials");
        JButton pathButton = new JButton("Choose Database Location");
        JTextField pathLabel = new JTextField();
        pathLabel.setEditable(false);
        JLabel dbUser = new JLabel("Database Username");
        JLabel dbPassword = new JLabel("Database Password");
        JLabel dbEncryptionPassword = new JLabel("Encryption Password");

        createButton.addActionListener(_ -> onSave());

        pathButton.addActionListener(_ -> {
            int result = chooser.showSaveDialog(this);

            if (result == JFileChooser.APPROVE_OPTION) {
                File selected = chooser.getSelectedFile();
                path = selected.getAbsolutePath();
                pathLabel.setText(path);
            }
        });

        add(PanelBuilder.buildJPanelWithFields(
                title, description,
                pathLabel, pathButton,
                dbUser, dbUserText,
                dbPassword, PanelBuilder.passwordField(dbPasswordText),
                dbEncryptionPassword, PanelBuilder.passwordField(dbEncryptionPasswordText),
                createButton
        ));
    }

    private void onSave() {
        String user = dbUserText.getText().trim();
        String password = new String(dbPasswordText.getPassword());
        String encPassword = new String(dbEncryptionPasswordText.getPassword());

        if (path == null || path.isBlank()) {
            error("Please choose a database location.");
            return;
        }
        if (user.isEmpty() || password.isEmpty() || encPassword.isEmpty()) {
            error("Username, password, and encryption password are required.");
            return;
        }

        BackgroundTask.run(this, createButton,
                () -> factory.create(path, user, password, encPassword),
                onComplete);
    }

    private void error(String message) {
        JOptionPane.showMessageDialog(this, message, "Data Store Setup", JOptionPane.ERROR_MESSAGE);
    }
}