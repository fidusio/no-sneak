package io.xlogistx.nosneak.app.mock;

import io.xlogistx.gui.IconStatusWidget;
import io.xlogistx.nosneak.app.mock.utility.AppContext;
import io.xlogistx.nosneak.app.mock.utility.BackgroundTask;
import io.xlogistx.nosneak.app.mock.utility.CardStack;
import io.xlogistx.nosneak.app.mock.utility.PanelBuilder;

import javax.swing.*;
import java.awt.*;
import java.net.URL;

public class LoginPanel extends JPanel {
    private final JTextField username = new JTextField(20);
    private final JTextField domain = new JTextField(20);
    private final JPasswordField password = new JPasswordField(20);
    private final JPasswordField confirmPassword = new JPasswordField(20);
    private final JLabel confirmPasswordLabel = new JLabel("Confirm Password");
    private final JPasswordField apiKey = new JPasswordField(30);
    private final CardStack cardStack = new CardStack();

    // Authentication-method selectors; API key is login-only.
    private final JToggleButton passwordSelector = new JToggleButton("Subject / Password");
    private final JToggleButton apiKeySelector = new JToggleButton("API Key");
    private final JToggleButton passkeySelector = new JToggleButton("Passkey");

    // Action buttons whose label/behavior flip between Login and Register.
    private final JButton passwordAction = new JButton();
    private final JButton apiKeyAction = new JButton();
    private final JButton passkeyAction = new JButton();
    private final JButton modeToggle = new JButton();
    private final PanelBuilder panelBuilder = new PanelBuilder();

    private boolean login = true;

    public LoginPanel(AppContext ctx) {
        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 6, 6, 6);

        // One card per authentication method. Login vs. Register is a mode that
        // re-labels the action button, not a separate set of cards.
        cardStack.add(buildPasswordScreen(), "Password");
        cardStack.add(buildAPIKeyScreen(), "APIKey");
        cardStack.add(buildPasskeyScreen(), "Passkey");
        cardStack.show("Password");

        // Action buttons branch on the current mode at click time.
        passwordAction.addActionListener(e -> {
            String user = username.getText();
            char[] pwd = password.getPassword();

            if (login) {

                BackgroundTask.runReason(this, passwordAction,
                        () -> ctx.session().loginUsernamePassword(user, pwd) ? null : "Invalid Credentials",
                        null);
            } else {
                if (!java.util.Arrays.equals(pwd, confirmPassword.getPassword())) {
                    JOptionPane.showMessageDialog(this, "Passwords do not match.", "Register",
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }
                BackgroundTask.runReason(this, passwordAction,
                        () -> ctx.session().registerUsernamePassword(user, pwd),
                        () -> {
                            JOptionPane.showMessageDialog(this, "Registered Successfully");
                            password.setText("");
                            confirmPassword.setText("");
                            username.setText("");
                            apiKey.setText("");
                            toggleMode();
                        });
            }
        });
        apiKeyAction.addActionListener(e -> {
            if (login) {
                BackgroundTask.runReason(this, passwordAction,
                        () -> ctx.session().loginAPIKey(apiKey.getPassword()),
                        () -> {
                        });
                ;
            }
        });
        passkeyAction.addActionListener(e -> {
            if (login) ctx.session().loginPasskey();
            else ctx.session().registerPasskey();
        });
        modeToggle.addActionListener(e -> toggleMode());
        applyMode();

        ctx.session().onAuthChange(e -> {
            if (!(boolean) e.getNewValue()) {
                password.setText("");
                username.setText("");
                apiKey.setText("");
            }
        });

        // Add Image @TODO probably replace with local image
        IconStatusWidget stateIcon = new IconStatusWidget(40, 40);
        try {
            Icon xlogistxIcon = new ImageIcon(new URL("https://xlogistx.io/favicon.ico"));
            stateIcon.mapStatus("xlogistx", xlogistxIcon);
            stateIcon.setStatus("xlogistx");
        } catch (Exception _) {

        }
        c.gridx = 0;
        c.gridwidth = 2;
        c.anchor = GridBagConstraints.CENTER;
        c.fill = GridBagConstraints.NONE;

        c.gridy = 1;
        add(stateIcon, c);

        // Add Title
        c.gridy = 2;
        JLabel title = PanelBuilder.title("NoSneak");
        add(title, c);

        // Add Wordmark
        c.gridy = 3;
        JLabel wordMark = new JLabel("Post-quantum secure access");
        add(wordMark, c);

        // Login pane selector buttons
        JPanel buttons = buildSelectorPane();
        c.gridy = 4;
        add(buttons, c);

        // Build each login pane
        c.gridy = 5;
        add(cardStack.view(), c);

        // Login <-> Register mode toggle
        c.gridy = 6;
        add(modeToggle, c);
    }

    private JPanel buildSelectorPane() {
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        ButtonGroup selector = new ButtonGroup();

        passwordSelector.addActionListener(e -> cardStack.show("Password"));
        apiKeySelector.addActionListener(e -> cardStack.show("APIKey"));
        passkeySelector.addActionListener(e -> cardStack.show("Passkey"));

        passwordSelector.setSelected(true);

        selector.add(passwordSelector);
        selector.add(apiKeySelector);
        selector.add(passkeySelector);

        buttons.add(passwordSelector);
        buttons.add(apiKeySelector);
        buttons.add(passkeySelector);
        passkeySelector.setVisible(false);

        return buttons;
    }

    private JPanel buildPasswordScreen() {
        return panelBuilder.buildJPanelWithFields(new JLabel("Username"), username, new JLabel("Password"), password, confirmPasswordLabel, confirmPassword, new JLabel("DomainAppID — optional"), domain, passwordAction);
    }

    private JPanel buildAPIKeyScreen() {
        return panelBuilder.buildJPanelWithFields(new JLabel("API Key"), apiKey, apiKeyAction);
    }

    private JPanel buildPasskeyScreen() {
        return panelBuilder.buildJPanelWithFields(new JLabel("NOT IMPLEMENTED"), passkeyAction);
    }

    private void toggleMode() {
        login = !login;
        applyMode();
    }

    private void applyMode() {
        String action = login ? "Login" : "Register";
        passwordAction.setText(action);
        apiKeyAction.setText(action);
        passkeyAction.setText(action);
        modeToggle.setText(login ? "Need an account? Register" : "Already have an account? Login");

        // Confirm-password is only collected when registering.
        confirmPasswordLabel.setVisible(!login);
        confirmPassword.setVisible(!login);
        if (login) {
            confirmPassword.setText("");
        }

        // API key registration is not allowed — selector is login-only.
        apiKeySelector.setVisible(login);
        if (!login && apiKeySelector.isSelected()) {
            passwordSelector.setSelected(true);
            cardStack.show("Password");
        }
    }
}
