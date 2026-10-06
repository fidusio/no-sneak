package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.Arrays;
import java.util.function.Consumer;

/**
 * The first screen when the app starts without launch parameters. The subject picks the
 * installation directory and types the <b>vault password</b>; when the directory already holds
 * a vault ({@link NoSneakStore#vaultExists}) that is all that is needed — the database settings
 * come from the vault. When it does not, the screen is the first-run setup and also asks for the
 * database user, password and encryption password that go into the new vault
 * ({@link NoSneakStore#create}). The three database rows show only in that case.
 */
public class DataStoreSetupPanel extends JPanel {

    /**
     * Opens (or creates) the installation from the collected fields and returns the resulting
     * manager. Runs off the EDT, so it may block and throw. {@code user}, {@code password} and
     * {@code encPassword} are null when the location already holds a vault.
     */
    @FunctionalInterface
    public interface DataStoreFactory {
        ShiroDSDomainSecurityManager create(String location, char[] vaultPassword,
                                            String user, String password, String encPassword) throws Exception;
    }

    private String path;
    private final JPasswordField vaultPasswordText = new JPasswordField(20);
    private final JTextField dbUserText = PanelBuilder.textField("", 20);
    private final JPasswordField dbPasswordText = new JPasswordField(20);
    private final JPasswordField dbEncryptionPasswordText = new JPasswordField(20);
    private final JLabel modeLabel = new JLabel(" ");
    private final JLabel dbUser = new JLabel("Database Username");
    private final JLabel dbPassword = new JLabel("Database Password");
    private final JLabel dbEncryptionPassword = new JLabel("Database Encryption Password");
    private final JPanel dbPasswordField = PanelBuilder.passwordField(dbPasswordText);
    private final JPanel dbEncryptionPasswordField = PanelBuilder.passwordField(dbEncryptionPasswordText);
    private final JButton createButton = new JButton("Open");
    private final DataStoreFactory factory;
    private final Consumer<ShiroDSDomainSecurityManager> onComplete;
    private boolean creating = true;

    public DataStoreSetupPanel(DataStoreFactory factory, Consumer<ShiroDSDomainSecurityManager> onComplete) {
        this.factory = factory;
        this.onComplete = onComplete;

        setLayout(new BorderLayout());

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose Location");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setCurrentDirectory(new File(System.getProperty("user.home")));

        JLabel title = PanelBuilder.title("Data Store Setup");
        JLabel description = new JLabel("Choose the no-sneak directory and enter its vault password");
        JButton pathButton = new JButton("Choose Location");
        JTextField pathLabel = new JTextField();
        pathLabel.setEditable(false);
        JLabel vaultPassword = new JLabel("Vault Password");
        modeLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

        createButton.addActionListener(_ -> onSave());

        pathButton.addActionListener(_ -> {
            int result = chooser.showSaveDialog(this);

            if (result == JFileChooser.APPROVE_OPTION) {
                File selected = chooser.getSelectedFile();
                path = selected.getAbsolutePath();
                pathLabel.setText(path);
                applyMode(!NoSneakStore.vaultExists(path));
            }
        });

        add(PanelBuilder.buildJPanelWithFields(
                title, description,
                pathLabel, pathButton,
                modeLabel,
                vaultPassword, PanelBuilder.passwordField(vaultPasswordText),
                dbUser, dbUserText,
                dbPassword, dbPasswordField,
                dbEncryptionPassword, dbEncryptionPasswordField,
                createButton
        ));
        applyMode(true);
    }

    /** First run (no vault at the location) shows the database rows; an existing vault hides them. */
    private void applyMode(boolean create) {
        creating = create;
        for (JComponent c : new JComponent[]{dbUser, dbUserText, dbPassword, dbPasswordField,
                dbEncryptionPassword, dbEncryptionPasswordField}) {
            c.setVisible(create);
        }
        createButton.setText(create ? "Create" : "Open");
        modeLabel.setText(path == null ? " "
                : create ? "No vault here: a new vault and database will be created."
                : "Existing vault found: enter its password.");
        revalidate();
        repaint();
    }

    private void onSave() {
        char[] vaultPassword = vaultPasswordText.getPassword();
        String user = dbUserText.getText().trim();
        String password = new String(dbPasswordText.getPassword());
        String encPassword = new String(dbEncryptionPasswordText.getPassword());

        if (path == null || path.isBlank()) {
            error("Please choose a location.");
            return;
        }
        if (vaultPassword.length == 0) {
            error("The vault password is required.");
            return;
        }
        // the directory may have gained or lost its vault since it was chosen
        boolean create = !NoSneakStore.vaultExists(path);
        if (create != creating) {
            applyMode(create);
        }
        if (create && (user.isEmpty() || password.isEmpty() || encPassword.isEmpty())) {
            error("Database username, password and encryption password are required to create the store.");
            return;
        }

        BackgroundTask.run(this, createButton,
                () -> {
                    try {
                        return create
                                ? factory.create(path, vaultPassword, user, password, encPassword)
                                : factory.create(path, vaultPassword, null, null, null);
                    } finally {
                        Arrays.fill(vaultPassword, '\0');
                    }
                },
                onComplete);
    }

    private void error(String message) {
        JOptionPane.showMessageDialog(this, message, "Data Store Setup", JOptionPane.ERROR_MESSAGE);
    }
}
