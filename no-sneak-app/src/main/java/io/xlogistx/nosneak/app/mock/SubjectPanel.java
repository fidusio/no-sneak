package io.xlogistx.nosneak.app.mock;

import io.xlogistx.nosneak.app.mock.utility.*;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.PrincipalIdentifier;
import org.zoxweb.shared.security.SubjectAPIKey;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SubjectPanel extends JPanel {
    private final CardStack cardStack = new CardStack();
    private final PanelBuilder panelBuilder = new PanelBuilder();
    private final AppContext ctx;

    // Profile text boxes
    private final JTextField firstName = new JTextField(20);
    private final JTextField lastName = new JTextField(20);
    private final JTextField dob = new JTextField(20);
    private final JTextField street = new JTextField(20);
    private final JTextField city = new JTextField(20);
    private final JTextField region = new JTextField(20);
    private final JTextField postCode = new JTextField(20);
    private final JTextField country = new JTextField(20);

    private static final String[] PROFILE_KEYS =
            {"firstName", "lastName", "dob", "street", "city", "region", "postCode", "country"};
    private final JButton saveProfile = new JButton("Save Changes");

    // Change-password form
    private final JPasswordField currentPwd = new JPasswordField(20);
    private final JPasswordField newPwd = new JPasswordField(20);
    private final JPasswordField confirmPwd = new JPasswordField(20);

    // Edit-API-key form: fields are populated from whichever key the user clicks in the list.
    private final JPasswordField editKeySecret = new JPasswordField(30);
    private final JTextField editKeyLabel = new JTextField(20);
    private final JTextField editKeyDescription = new JTextField(20);
    private SubjectAPIKey selectedKey;
    private boolean isKeyShown = false;
    private final char defaultEcho = editKeySecret.getEchoChar();
    private final JButton showKey = new JButton("Show");

    // Data-driven sections (refreshed on auth) + credential detail switching
    private ListSection identifiers;
    private ListSection passwordSection;
    private ListSection apiKeySection;
    private final CardStack credentialCards = new CardStack();

    public SubjectPanel(AppContext ctx) {
        setLayout(new BorderLayout());
        this.ctx = ctx;

        cardStack.add(new JScrollPane(buildProfile()), "Profile");
        cardStack.add(new JScrollPane(buildCredentials()), "Credentials");
        cardStack.show("Profile");

        JToggleButton profileButton = new JToggleButton("Profile");
        profileButton.addActionListener(e -> cardStack.show("Profile"));
        JToggleButton credentialButton = new JToggleButton("Login credential");
        credentialButton.addActionListener(e -> cardStack.show("Credentials"));

        // Panels are built once (before login). Refresh on both login and logout: the Session
        // getters return empty once logged out, so this also clears the previous subject's rows
        // instead of leaving them stale, and resets the credential view.
        ctx.session().onAuthChange(e -> {
            identifiers.refresh();
            passwordSection.refresh();
            apiKeySection.refresh();
            populateProfile();
            if (!(boolean) e.getNewValue()) {
                credentialCards.show("list");
                currentPwd.setText("");
                newPwd.setText("");
                confirmPwd.setText("");
                firstName.setText("");
                lastName.setText("");
                dob.setText("");
                street.setText("");
                city.setText("");
                region.setText("");
                postCode.setText("");
                country.setText("");
                editKeySecret.setText("");
                editKeyLabel.setText("");
                editKeyDescription.setText("");
            }
        });

        add(panelBuilder.buildDefaultSplitPanel(cardStack.view(), profileButton, credentialButton));
    }

    // ---- Profile (+ Identifiers) ----

    private JPanel buildProfile() {
        identifiers = new ListSection("Identifiers", "+ Add identifier",
                this::onAddIdentifier, this::identifierEntries);

        saveProfile.addActionListener(e -> onSaveProfile());

        return panelBuilder.buildJPanelWithFields(
                PanelBuilder.title("Profile"),
                new JLabel("Details about your account. Some fields are managed by the system and can't be changed."),
                new JLabel("First name"),
                firstName,
                new JLabel("Last name"),
                lastName,
                identifiers,
                new JLabel("Date of birth — optional"),
                dob,
                new JLabel("Mailing address"),
                new JLabel("Optional postal address for billing or shipping."),
                new JLabel("Street — optional"),
                street,
                new JLabel("City"),
                city,
                new JLabel("State / region"),
                region,
                new JLabel("Postal code"),
                postCode,
                new JLabel("Country"),
                country,
                saveProfile
        );
    }

    private List<ListSection.Entry> identifierEntries() {
        List<ListSection.Entry> out = new ArrayList<>();
        for (PrincipalIdentifier p : ctx.session().getAllPrincipalIDForLoggedInUser()) {
            out.add(new ListSection.Entry(p.getPrincipalID(), null, () -> onRemoveIdentifier(p)));
        }
        return out;
    }

    private void onAddIdentifier() {
        String id = JOptionPane.showInputDialog(this, "New email / username / handle:");
        if (id == null || id.isBlank()) return;
        BackgroundTask.runReason(this, null,
                () -> ctx.session().addIdentifier(id.trim()),
                () -> identifiers.refresh());
    }

    private void onRemoveIdentifier(PrincipalIdentifier p) {

        BackgroundTask.runReason(this, null,
                () -> ctx.session().removeIdentifier(p),
                () -> identifiers.refresh());
    }

    // ---- Login credentials (+ change password) ----

    private JPanel buildCredentials() {
        credentialCards.add(buildCredentialList(), "list");
        credentialCards.add(buildChangePassword(), "changePassword");
        credentialCards.add(buildEditAPIKey(), "editAPI");
        credentialCards.show("list");

        JPanel p = new JPanel(new BorderLayout());
        p.add(credentialCards.view(), BorderLayout.CENTER);
        return p;
    }

    private JPanel buildCredentialList() {
        passwordSection = new ListSection("Password", null, null, this::passwordEntries);
        apiKeySection = new ListSection("API keys", "+ Add API Key", this::addCredentialPage, this::apiKeyEntries);

        JLabel header = PanelBuilder.title("Login credentials");
        JLabel desc = new JLabel("One password, plus any number of API keys.");

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        for (JComponent c : new JComponent[]{header, desc, passwordSection, apiKeySection}) {
            c.setAlignmentX(Component.LEFT_ALIGNMENT);
        }
        content.add(header);
        content.add(Box.createVerticalStrut(2));
        content.add(desc);
        content.add(Box.createVerticalStrut(12));
        content.add(passwordSection);
        content.add(Box.createVerticalStrut(12));
        content.add(apiKeySection);

        JPanel p = new JPanel(new BorderLayout());
        p.add(content, BorderLayout.NORTH);   // hug the top; leftover space stays at the bottom
        return p;
    }

    private void addCredentialPage() {

        String generated = ctx.session().generateAPIKey();

        // --- Generate card: label + read-only (copyable) key + Copy ---
        JTextField genLabel = new JTextField(20);
        JTextField genDescription = new JTextField(20);
        JTextField genKey = new JTextField(generated, 30);
        genKey.setEditable(false);               // selectable + copyable, not editable
        JButton copy = new JButton("Copy");
        copy.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(generated), null);
            copy.setText("Copied!");
        });
        JPanel copyRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        copyRow.add(genKey);
        copyRow.add(copy);
        JPanel generateCard = panelBuilder.buildJPanelWithFields(
                new JLabel("Label"), genLabel, new JLabel("Description"), genDescription,
                new JLabel("Copy this key now"), copyRow);

        // --- Enter-existing card: label + paste field ---
        JTextField inLabel = new JTextField(30);
        JTextField inDescription = new JTextField(30);
        JTextField inAppID = new JTextField(30);
        JTextField inDomainID = new JTextField(30);
        JTextField inKey = new JTextField(30);
        JPanel inputCard = panelBuilder.buildJPanelWithFields(
                new JLabel("Label"), inLabel, new JLabel("Description"), inDescription,
                new JLabel("App Id"), inAppID, new JLabel("Domain ID"), inDomainID,
                new JLabel("Paste existing key"), inKey);

        // --- selector + cards ---
        CardStack cards = new CardStack();
        cards.add(generateCard, "generate");
        cards.add(inputCard, "input");
        cards.show("generate");

        JToggleButton generateButton = new JToggleButton("Generate local key", true);
        JToggleButton existingButton = new JToggleButton("Add third party key");
        ButtonGroup selector = new ButtonGroup();
        selector.add(generateButton);
        selector.add(existingButton);
        generateButton.addActionListener(e -> cards.show("generate"));
        existingButton.addActionListener(e -> cards.show("input"));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttons.add(generateButton);
        buttons.add(existingButton);

        JPanel dialog = panelBuilder.buildJPanelWithFields(
                PanelBuilder.title("Generate a new key, or enter one you already have."),
                buttons, cards.view());

        String[] actions = {"Create key", "Cancel"};
        int result = JOptionPane.showOptionDialog(this, dialog, "Add API key",
                JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, actions, actions[0]);
        if (result != 0) return;   // Cancel or dialog closed

        boolean generating = generateButton.isSelected();
        String label = generating ? genLabel.getText() : inLabel.getText();
        String description = generating ? genDescription.getText() : inDescription.getText();
        String appId = generating ? "" : inAppID.getText().trim();
        String domainId = generating ? "" : inDomainID.getText().trim();
        String key = generating ? generated : inKey.getText().trim();

        // An external (third party) key requires both the App Id and the key.
        if (!generating && (appId.isBlank() || key.isBlank())) {
            JOptionPane.showMessageDialog(this,
                    "Enter both the App Id and the key to add a third party API key.",
                    "Missing information", JOptionPane.WARNING_MESSAGE);
            return;
        }

        BackgroundTask.runReason(this, null,
                () -> ctx.session().createAPIKey(label, description,domainId, appId, key),
                () -> {
                    passwordSection.refresh();
                    apiKeySection.refresh();
                    JOptionPane.showMessageDialog(this, "API key added.");
                });
    }

    private List<ListSection.Entry> passwordEntries() {
        List<ListSection.Entry> out = new ArrayList<>();

        for (CredentialInfo ci : ctx.session().getAllCredentialForLoggedInUser()) {
            if (ci.getCredentialType() == CredentialInfo.Type.PASSWORD) {
                out.add(new ListSection.Entry("Password",
                        () -> credentialCards.show("changePassword"), null));
            }
        }
        if (out.isEmpty()) out.add(new ListSection.Entry("No password set", null, null));
        return out;
    }

    private List<ListSection.Entry> apiKeyEntries() {
        List<ListSection.Entry> out = new ArrayList<>();

        for (CredentialInfo ci : ctx.session().getAllCredentialForLoggedInUser()) {
            if (ci.getCredentialType() != CredentialInfo.Type.PASSWORD) {
                SubjectAPIKey key = (SubjectAPIKey) ci;
                String label = key.getName();
                String display = (label == null || label.isBlank()) ? "API key" : "API key — " + label;
                out.add(new ListSection.Entry(display, () -> showEditAPIKey(key), null));
            }
        }
        if (out.isEmpty()) out.add(new ListSection.Entry("No API keys yet", null, null));
        return out;
    }

    private JPanel buildChangePassword() {
        JButton submit = new JButton("Change password");
        submit.addActionListener(e -> onChangePassword(submit));

        return PanelBuilder.detail("Change password",
                () -> credentialCards.show("list"),
                panel -> {
                    panel.add(new JLabel("Current password"));
                    panel.add(currentPwd);
                    panel.add(new JLabel("New password"));
                    panel.add(newPwd);
                    panel.add(new JLabel("Confirm new password"));
                    panel.add(confirmPwd);
                    panel.add(submit);
                });
    }

    private JPanel buildEditAPIKey() {
        JButton submit = new JButton("Edit API Key");
        JButton copyKey = new JButton("Copy");
        submit.addActionListener(e -> onEditAPIDetails(submit));
        copyKey.addActionListener(e -> {
            if (selectedKey != null && selectedKey.getAPIKey() != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(selectedKey.getAPIKey()), null);
                copyKey.setText("Copied!");
            }
        });

        // Toggle: masking is currently on when isKeyShown is false, so flip it.
        showKey.addActionListener(e -> setKeyMasked(isKeyShown));

        editKeySecret.setEditable(false);   // the stored secret, shown read-only

        JPanel keyView = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keyView.add(editKeySecret);
        keyView.add(copyKey);
        keyView.add(showKey);

        JButton rotate = new JButton("Rotate");
        rotate.addActionListener(e -> onRotateAPIKey(rotate));
        JButton revoke = new JButton("Revoke");
        revoke.addActionListener(e -> onRevokeAPIKey(revoke));

        JPanel apiButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        apiButtons.add(rotate);
        apiButtons.add(revoke);

        return PanelBuilder.detail("Edit API key",
                () -> credentialCards.show("list"),
                panel -> {
                    panel.add(new JLabel("Secret key"));
                    panel.add(keyView);

                    panel.add(new JLabel("Label"));
                    panel.add(editKeyLabel);

                    panel.add(new JLabel("Description"));
                    panel.add(editKeyDescription);

                    panel.add(submit);

                    panel.add(PanelBuilder.title("Rotate or Revoke"));
                    panel.add(new JLabel("Rotating issues a new secret for this key and invalidates the current one."));
                    panel.add(apiButtons);
                }
        );
    }

    /**
     * Single place that keeps the echo char, the button label, and {@link #isKeyShown} in sync.
     */
    private void setKeyMasked(boolean masked) {
        editKeySecret.setEchoChar(masked ? defaultEcho : (char) 0);
        showKey.setText(masked ? "Show" : "Hide");
        isKeyShown = !masked;
    }

    private void showEditAPIKey(SubjectAPIKey key) {
        selectedKey = key;
        editKeySecret.setText(key.getAPIKey());
        editKeySecret.setCaretPosition(0);
        setKeyMasked(true);   // every key opens hidden, regardless of the previous selection
        editKeyLabel.setText(key.getName());
        editKeyDescription.setText(key.getDescription());
        credentialCards.show("editAPI");
    }

    private void onRotateAPIKey(JButton src) {
        if (selectedKey == null) return;
        int ok = JOptionPane.showConfirmDialog(this,
                "Rotate this key? The current secret stops working immediately.",
                "Rotate API key", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        BackgroundTask.runReason(this, src,
                () -> ctx.session().rotateAPIKey(selectedKey),
                () -> {
                    // rotate mutates selectedKey in place; re-populate so the new secret shows.
                    showEditAPIKey(selectedKey);
                    apiKeySection.refresh();
                    JOptionPane.showMessageDialog(this, "Key rotated. Copy the new secret now.");
                });
    }

    private void onRevokeAPIKey(JButton src) {
        if (selectedKey == null) return;
        int ok = JOptionPane.showConfirmDialog(this,
                "Revoke this key? This permanently removes it.",
                "Revoke API key", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        BackgroundTask.runReason(this, src,
                () -> ctx.session().revokeAPIKey(selectedKey),
                () -> {
                    selectedKey = null;
                    credentialCards.show("list");   // the edit card now points at a deleted key
                    apiKeySection.refresh();
                    JOptionPane.showMessageDialog(this, "API key revoked.");
                });
    }

    private void onChangePassword(JButton submit) {
        char[] cur = currentPwd.getPassword();
        char[] next = newPwd.getPassword();

        if (!java.util.Arrays.equals(next, confirmPwd.getPassword())) {
            JOptionPane.showMessageDialog(this, "New passwords do not match.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        BackgroundTask.runReason(this, submit,
                () -> ctx.session().changePassword(cur, next),
                () -> {
                    JOptionPane.showMessageDialog(this, "Password changed.");
                    currentPwd.setText("");
                    newPwd.setText("");
                    confirmPwd.setText("");
                    credentialCards.show("list");
                    passwordSection.refresh();
                    apiKeySection.refresh();

                });
    }

    private void onEditAPIDetails(JButton submit) {

        BackgroundTask.runReason(this, submit,
                () -> ctx.session().changeAPIDetails(selectedKey, editKeyLabel.getText(), editKeyDescription.getText()),
                () -> {
                    JOptionPane.showMessageDialog(this, "API Key updated");
                    selectedKey = null;
                    editKeySecret.setText("");
                    editKeyLabel.setText("");
                    editKeyDescription.setText("");
                    credentialCards.show("list");
                    passwordSection.refresh();
                    apiKeySection.refresh();
                });
    }

    private void onSaveProfile() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("firstName", firstName.getText());
        fields.put("lastName", lastName.getText());
        fields.put("dob", dob.getText());
        fields.put("street", street.getText());
        fields.put("city", city.getText());
        fields.put("region", region.getText());
        fields.put("postCode", postCode.getText());
        fields.put("country", country.getText());
        BackgroundTask.runReason(this, null,
                () -> ctx.session().saveProfile(fields),
                () -> {
                    JOptionPane.showMessageDialog(this, "Profile saved.");
                });
    }

    private void populateProfile() {
        Map<String, String> p = ctx.session().loadProfile(PROFILE_KEYS);
        firstName.setText(p.get("firstName"));
        lastName.setText(p.get("lastName"));
        dob.setText(p.get("dob"));
        street.setText(p.get("street"));
        city.setText(p.get("city"));
        region.setText(p.get("region"));
        postCode.setText(p.get("postCode"));
        country.setText(p.get("country"));

    }
}
