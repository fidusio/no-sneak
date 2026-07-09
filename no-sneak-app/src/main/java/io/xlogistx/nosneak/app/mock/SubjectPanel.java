package io.xlogistx.nosneak.app.mock;

import com.formdev.flatlaf.extras.FlatSVGIcon;
import io.xlogistx.nosneak.app.mock.utility.*;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.PrincipalIdentifier;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.util.NVGenericMap;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SubjectPanel extends JPanel {

    // ---- Services ----
    private final CardStack cardStack = new CardStack();
    private final PanelBuilder panelBuilder = new PanelBuilder();
    private final AppContext ctx;

    // ---- Profile fields ----
    private final JTextField firstName = new JTextField(20);
    private final JTextField lastName = new JTextField(20);
    private final JTextField dob = new JTextField(20);

    private static final String[] PROFILE_KEYS = {"firstName", "lastName", "dob"};
    private final JButton saveProfile = new JButton("Save Changes", new FlatSVGIcon("icons/save.svg", 16, 16));

    // ---- Change-password fields ----
    private final JPasswordField currentPwd = new JPasswordField(20);
    private final JPasswordField newPwd = new JPasswordField(20);
    private final JPasswordField confirmPwd = new JPasswordField(20);

    // ---- Edit-API-key fields (populated from whichever key the user clicks in the list) ----
    private final JPasswordField editKeySecret = new JPasswordField(30);
    private final JTextField editKeyLabel = new JTextField(20);
    private final JTextField editKeyDescription = new JTextField(20);
    private SubjectAPIKey selectedKey;
    private boolean isKeyShown = false;
    private final char defaultEcho = editKeySecret.getEchoChar();
    private final JButton showKey = new JButton(new FlatSVGIcon("icons/eye.svg", 16, 16));

    // ---- Edit-address fields (populated from the clicked address; null selection = new address) ----
    private final JTextField addrLabel = new JTextField(20);
    private final JTextField addrStreet = new JTextField(20);
    private final JTextField addrCity = new JTextField(20);
    private final JTextField addrRegion = new JTextField(20);
    private final JTextField addrPostCode = new JTextField(20);
    private final JTextField addrCountry = new JTextField(20);
    private NVGenericMap selectedAddress;

    // ---- Data-driven sections (refreshed on auth) + detail card switching ----
    private ListSection identifiers;
    private ListSection addressSection;
    private ListSection passwordSection;
    private ListSection apiKeySection;
    private final CardStack profileCards = new CardStack();
    private final CardStack credentialCards = new CardStack();

    public SubjectPanel(AppContext ctx) {
        setLayout(new BorderLayout());
        this.ctx = ctx;

        cardStack.add(new JScrollPane(buildProfileArea()), "Profile");
        cardStack.add(new JScrollPane(buildCredentials()), "Credentials");
        cardStack.show("Profile");

        JToggleButton profileButton = new JToggleButton("Profile");
        profileButton.addActionListener(_ -> cardStack.show("Profile"));
        JToggleButton credentialButton = new JToggleButton("Credentials");
        credentialButton.addActionListener(_ -> cardStack.show("Credentials"));

        // Panels are built once (before login). Refresh on both login and logout: the Session
        // getters return empty once logged out, so this also clears the previous subject's rows
        // instead of leaving them stale, and resets the credential view.
        ctx.session().onAuthChange(e -> {
            identifiers.refresh();
            addressSection.refresh();
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
                editKeySecret.setText("");
                editKeyLabel.setText("");
                editKeyDescription.setText("");
                selectedKey = null;
                profileCards.show("profile");
                addrLabel.setText("");
                addrStreet.setText("");
                addrCity.setText("");
                addrRegion.setText("");
                addrPostCode.setText("");
                addrCountry.setText("");
                selectedAddress = null;
            }
        });

        add(panelBuilder.buildDefaultSplitPanel(cardStack.view(), profileButton, credentialButton));
    }

    // ============================ Profile & identifiers ============================

    private JPanel buildProfileArea() {
        profileCards.add(buildProfile(), "profile");
        profileCards.add(buildEditAddress(), "editAddress");
        profileCards.show("profile");

        JPanel p = new JPanel(new BorderLayout());
        p.add(profileCards.view(), BorderLayout.CENTER);
        return p;
    }

    private JPanel buildProfile() {
        identifiers = new ListSection("Identifiers", "+ Add identifier",
                this::onAddIdentifier, this::identifierEntries);
        addressSection = new ListSection("Addresses", "+ Add address",
                this::onAddAddress, this::addressEntries);

        saveProfile.addActionListener(_ -> onSaveProfile());

        return panelBuilder.buildJPanelWithFields(
                PanelBuilder.title("Profile"),
                new JLabel("Details about your account. Some fields are managed by the system and can't be changed."),
                new JLabel("First name"),
                firstName,
                new JLabel("Last name"),
                lastName,
                new JLabel("Date of birth — optional"),
                dob,
                saveProfile,
                identifiers,
                addressSection

        );
    }

    private void onSaveProfile() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("firstName", firstName.getText());
        fields.put("lastName", lastName.getText());
        fields.put("dob", dob.getText());
        BackgroundTask.runCatching(this, null,
                () -> ctx.session().saveProfile(fields),
                () -> JOptionPane.showMessageDialog(this, "Profile saved."));
    }

    private void populateProfile() {
        Map<String, String> p = ctx.session().loadProfile(PROFILE_KEYS);
        firstName.setText(p.get("firstName"));
        lastName.setText(p.get("lastName"));
        dob.setText(p.get("dob"));
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
        BackgroundTask.runCatching(this, null,
                () -> ctx.session().addIdentifier(id.trim()),
                () -> identifiers.refresh());
    }

    private void onRemoveIdentifier(PrincipalIdentifier p) {
        int ok = JOptionPane.showConfirmDialog(this,
                "Delete this identifier?", "Delete identifier",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;
        BackgroundTask.runCatching(this, null,
                () -> ctx.session().removeIdentifier(p),
                () -> identifiers.refresh());
    }

    private List<ListSection.Entry> addressEntries() {
        List<ListSection.Entry> out = new ArrayList<>();
        for (NVGenericMap address : ctx.session().getAddresses()) {
            out.add(new ListSection.Entry(addressLabel(address),
                    () -> onEditAddress(address), () -> onRemoveAddress(address)));
        }
        if (out.isEmpty()) out.add(new ListSection.Entry("No addresses yet", null, null));
        return out;
    }

    /**
     * Row label: the address's own label, else a "street, city" summary, else "Address".
     */
    private static String addressLabel(NVGenericMap a) {
        String label = a.getValue("label");
        if (label != null && !label.isBlank()) return label;
        String street = a.getValue("street");
        String city = a.getValue("city");
        String s = street == null ? "" : street.trim();
        String c = city == null ? "" : city.trim();
        String joined = (s.isBlank() || c.isBlank()) ? (s + c) : (s + ", " + c);
        return joined.isBlank() ? "Address" : joined;
    }

    private void onAddAddress() {
        showEditAddress(null);   // null selection = adding a new address
    }

    private void onEditAddress(NVGenericMap address) {
        showEditAddress(address);
    }

    private void onRemoveAddress(NVGenericMap address) {
        int ok = JOptionPane.showConfirmDialog(this,
                "Delete this address?", "Delete address",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;
        BackgroundTask.runCatching(this, null,
                () -> ctx.session().removeAddress(address),
                () -> addressSection.refresh());
    }

    /**
     * The address detail card (fields + Save), reached by "+ Add address" or a per-row Edit.
     */
    private JPanel buildEditAddress() {
        JButton save = new JButton("Save address", new FlatSVGIcon("icons/save.svg", 16, 16));
        save.addActionListener(_ -> onSaveAddress(save));

        return PanelBuilder.detail("Address",
                () -> profileCards.show("profile"),
                panel -> {
                    panel.add(new JLabel("Label — e.g. Home, Work"));
                    panel.add(addrLabel);
                    panel.add(new JLabel("Street"));
                    panel.add(addrStreet);
                    panel.add(new JLabel("City"));
                    panel.add(addrCity);
                    panel.add(new JLabel("State / region"));
                    panel.add(addrRegion);
                    panel.add(new JLabel("Postal code"));
                    panel.add(addrPostCode);
                    panel.add(new JLabel("Country"));
                    panel.add(addrCountry);
                    panel.add(save);
                });
    }

    /**
     * Opens the detail card populated from {@code address} (null = a blank, new address).
     */
    private void showEditAddress(NVGenericMap address) {
        selectedAddress = address;
        addrLabel.setText(text(address, "label"));
        addrStreet.setText(text(address, "street"));
        addrCity.setText(text(address, "city"));
        addrRegion.setText(text(address, "region"));
        addrPostCode.setText(text(address, "postCode"));
        addrCountry.setText(text(address, "country"));
        profileCards.show("editAddress");
    }

    private static String text(NVGenericMap map, String key) {
        if (map == null) return "";
        String v = map.getValue(key);
        return v == null ? "" : v;
    }

    private void onSaveAddress(JButton save) {
        boolean creating = selectedAddress == null;
        NVGenericMap address = creating ? new NVGenericMap() : selectedAddress;
        address.build("label", addrLabel.getText().trim());
        address.build("street", addrStreet.getText().trim());
        address.build("city", addrCity.getText().trim());
        address.build("region", addrRegion.getText().trim());
        address.build("postCode", addrPostCode.getText().trim());
        address.build("country", addrCountry.getText().trim());

        BackgroundTask.runCatching(this, save,
                () -> {
                    if (creating) ctx.session().addAddress(address);
                    else ctx.session().saveAddresses();   // address was mutated in place
                },
                () -> {
                    selectedAddress = null;
                    profileCards.show("profile");
                    addressSection.refresh();
                });
    }

    // ============================ Credentials (list) ============================

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

        JLabel header = PanelBuilder.title("Credentials");
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

    // ============================ Add API key ============================

    private void addCredentialPage() {

        APIKey<String> generated;
        try {
            generated = ctx.session().generateAPIKey();
        } catch (SecurityException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // --- Generate card: label + read-only (copyable) key + Copy ---
        JTextField genLabel = new JTextField(20);
        JTextField genDescription = new JTextField(20);
        JTextField genKey = new JTextField(generated.getAPIKey(), 30);
        genKey.setEditable(false);               // selectable + copyable, not editable
        JButton copy = new JButton(new FlatSVGIcon("icons/copy.svg", 16, 16));
        copy.setToolTipText("Copy");
        copy.addActionListener(_ -> {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(genKey.getText()), null);
            copy.setIcon(new FlatSVGIcon("icons/check.svg", 16, 16));
            copy.setToolTipText("Copied!");
        });
        JButton refresh = new JButton(new FlatSVGIcon("icons/rotate.svg", 16, 16));
        refresh.setToolTipText("Refresh");
        refresh.addActionListener(_ -> {
            APIKey<String> refreshed;
            try {
                refreshed = ctx.session().generateAPIKey();
            } catch (SecurityException e) {
                JOptionPane.showMessageDialog(this, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            genKey.setText(refreshed.getAPIKey());
        });
        JPanel copyRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        copyRow.add(genKey);
        copyRow.add(refresh);
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
        generateButton.addActionListener(_ -> cards.show("generate"));
        existingButton.addActionListener(_ -> cards.show("input"));

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
        String key = generating ? genKey.getText() : inKey.getText().trim();

        // An external (third party) key requires both the AppID and the key.
        if (!generating && (appId.isBlank() || key.isBlank())) {
            JOptionPane.showMessageDialog(this,
                    "Enter both the App Id and the key to add a third party API key.",
                    "Missing information", JOptionPane.WARNING_MESSAGE);
            return;
        }

        BackgroundTask.runCatching(this, null,
                () -> ctx.session().createAPIKey(label, description, domainId, appId, key),
                () -> {
                    passwordSection.refresh();
                    apiKeySection.refresh();
                    JOptionPane.showMessageDialog(this, "API key added.");
                });
    }

    // ============================ Change password ============================

    private JPanel buildChangePassword() {
        JButton submit = new JButton("Change password", new FlatSVGIcon("icons/save.svg", 16, 16));
        submit.addActionListener(_ -> onChangePassword(submit));

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

    private void onChangePassword(JButton submit) {
        char[] cur = currentPwd.getPassword();
        char[] next = newPwd.getPassword();

        if (!java.util.Arrays.equals(next, confirmPwd.getPassword())) {
            JOptionPane.showMessageDialog(this, "New passwords do not match.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        BackgroundTask.runCatching(this, submit,
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

    // ============================ Edit API key ============================

    private JPanel buildEditAPIKey() {
        JButton submit = new JButton(new FlatSVGIcon("icons/pencil.svg", 16, 16));
        submit.setToolTipText("Edit API Key");
        JButton copyKey = new JButton(new FlatSVGIcon("icons/copy.svg", 16, 16));
        copyKey.setToolTipText("Copy");
        submit.addActionListener(_ -> onEditAPIDetails(submit));
        copyKey.addActionListener(_ -> {
            if (selectedKey != null && selectedKey.getAPIKey() != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(selectedKey.getAPIKey()), null);
                copyKey.setIcon(new FlatSVGIcon("icons/check.svg", 16, 16));
                copyKey.setToolTipText("Copied!");
            }
        });

        // Toggle: masking is currently on when isKeyShown is false, so flip it.
        showKey.addActionListener(_ -> setKeyMasked(isKeyShown));

        editKeySecret.setEditable(false);

        JPanel keyView = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keyView.add(editKeySecret);
        keyView.add(copyKey);
        keyView.add(showKey);

        JButton rotate = new JButton(new FlatSVGIcon("icons/rotate.svg", 16, 16));
        rotate.setToolTipText("Rotate");
        rotate.addActionListener(_ -> onRotateAPIKey(rotate));

        JButton delete = new JButton(new FlatSVGIcon("icons/trash.svg", 16, 16));
        delete.setToolTipText("Delete");
        delete.addActionListener(_ -> onDeleteAPIKey(delete));

        JPanel apiButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        apiButtons.add(rotate);
        apiButtons.add(delete);

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

                    panel.add(PanelBuilder.title("Rotate or Delete"));
                    panel.add(new JLabel("Rotating issues a new secret for this key and invalidates the current one."));
                    panel.add(apiButtons);
                }
        );
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

    private void setKeyMasked(boolean masked) {
        editKeySecret.setEchoChar(masked ? defaultEcho : (char) 0);
        showKey.setIcon(new FlatSVGIcon(masked ? "icons/eye.svg" : "icons/eye-off.svg", 16, 16));
        showKey.setToolTipText(masked ? "Show" : "Hide");
        isKeyShown = !masked;
    }

    private void onEditAPIDetails(JButton submit) {
        BackgroundTask.runCatching(this, submit,
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

    private void onRotateAPIKey(JButton src) {
        if (selectedKey == null) return;
        int ok = JOptionPane.showConfirmDialog(this,
                "Rotate this key? The current secret stops working immediately.",
                "Rotate API key", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        BackgroundTask.runCatching(this, src,
                () -> ctx.session().rotateAPIKey(selectedKey),
                () -> {
                    // rotate mutates selectedKey in place; re-populate so the new secret shows.
                    showEditAPIKey(selectedKey);
                    apiKeySection.refresh();
                    JOptionPane.showMessageDialog(this, "Key rotated. Copy the new secret now.");
                });
    }

    private void onDeleteAPIKey(JButton src) {
        if (selectedKey == null) return;
        int ok = JOptionPane.showConfirmDialog(this,
                "Delete this key? This permanently removes it.",
                "Delete API key", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        BackgroundTask.runCatching(this, src,
                () -> ctx.session().deleteAPIKey(selectedKey),
                () -> {
                    selectedKey = null;
                    credentialCards.show("list");   // the edit card now points at a deleted key
                    apiKeySection.refresh();
                    JOptionPane.showMessageDialog(this, "API key Deleted.");
                });
    }
}
