package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.*;
import io.xlogistx.nosneak.app.ui.utility.*;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.data.DataConst;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.PrincipalIdentifier;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVPair;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.*;

import static io.xlogistx.gui.PanelBuilder.*;

public class SubjectPanel extends JPanel {

    // ---- Services ----
    private final CardStack cardStack = new CardStack();
    private final AppContext ctx;

    // ---- Profile fields ----
    private final JTextField firstName = new JTextField(20);
    private final JTextField lastName = new JTextField(20);
    private final JTextField dob = new JTextField(20);

    private static final String[] PROFILE_KEYS = {"firstName", "lastName", "dob"};
    private final JButton saveProfile = new JButton("Save Changes", new IconUtil.SaveIcon(16));

    // ---- Change-password fields ----
    private final JPasswordField currentPwd = new JPasswordField(20);
    private final JPasswordField newPwd = new JPasswordField(20);
    private final JPasswordField confirmPwd = new JPasswordField(20);

    // ---- Edit-API-key fields (populated from whichever key the user clicks in the list) ----
    private final JPasswordField editKeySecret = new JPasswordField(30);
    private final JTextField editKeyLabel = new JTextField(20);
    private final JTextField editKeyDescription = new JTextField(20);
    private final JTextField keyAppID = new JTextField(20);
    private final JTextField keyDomainID = new JTextField(20);
    private final JTextField keyProvider = new JTextField(20);
    private final JTextField keyURI = new JTextField(20);
    private final JTextField authScheme = new JTextField(20);
    private final JTextField headerName = new JTextField(20);
    private SubjectAPIKey selectedKey;
    private boolean isKeyShown = false;
    private final char defaultEcho = editKeySecret.getEchoChar();
    private final JButton showKey = GUIUtil.iconButton(new IconUtil.VisibleIcon(16));
    private final JButton rotateKey = GUIUtil.iconButton(new IconUtil.RefreshIcon(16));

    // ---- Edit-address fields (populated from the clicked address; null selection = new address) ----
    private final JTextField addrLabel = new JTextField(20);
    private final JTextField addrStreet = new JTextField(20);
    private final JTextField addrCity = new JTextField(20);
    private final JTextField addrRegion = new JTextField(20);
    private final JTextField addrPostCode = new JTextField(20);
    private final String[] countries = DataConst.COUNTRIES.getValue().stream()
            .map(NVPair::getValue)
            .toArray(String[]::new);
    private final JComboBox<String> addrCountry = new JComboBox<>(countries);
    private NVGenericMap selectedAddress;

    // Field keys for an address map (stored inline in the subject's property bag)
    private static final String A_LABEL = "label", A_STREET = "street", A_CITY = "city",
            A_STATE = "state", A_POSTAL = "postal", A_COUNTRY = "country";

    // ---- Data-driven sections (refreshed on auth) + detail card switching ----
    private ListSection<PrincipalIdentifier> identifiers;
    private ListSection<NVGenericMap> addressSection;
    private ListSection<CIPassword> passwordSection;
    private ListSection<SubjectAPIKey> apiKeySection;
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
                keyAppID.setText("");
                keyDomainID.setText("");
                keyProvider.setText("");
                keyURI.setText("");
                authScheme.setText("");
                headerName.setText("");
                selectedKey = null;
                setKeyMasked(true);
                profileCards.show("profile");
                addrLabel.setText("");
                addrStreet.setText("");
                addrCity.setText("");
                addrRegion.setText("");
                addrPostCode.setText("");
                selectedAddress = null;
                addrCountry.setSelectedIndex(-1);
            }
        });

        add(PanelBuilder.buildDefaultSplitPanel(cardStack.view(), profileButton, credentialButton));
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

        identifiers = ListSection.of(() -> Arrays.asList(ctx.session().getAllPrincipalIDForLoggedInUser()))
                .title("Identifiers")
                .addButton("+ Add identifier", this::onAddIdentifier)
                .label(PrincipalIdentifier::getPrincipalID)
                .onRemove(p -> () -> onRemoveIdentifier(p))
                .build();

        addressSection = ListSection.of(() -> ctx.session().getAllAddresses())
                .title("Addresses")
                .addButton("+ Add address", this::onAddAddress)
                .label(this::addressLabel)
                .onEdit(p -> () -> onEditAddress(p))
                .onRemove(p -> () -> onRemoveAddress(p))
                .emptyText("No addresses yet")
                .build();

        saveProfile.addActionListener(_ -> onSaveProfile());

        return PanelBuilder.buildJPanelWithFields(
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

    /**
     * Reads a string field from an address map, empty string when unset.
     */
    private static String field(NVGenericMap a, String key) {
        Object v = a.getValue(key);
        return v == null ? "" : v.toString();
    }

    /**
     * Row label: the address's own label, else a "street, city" summary, else "Address".
     */
    private String addressLabel(NVGenericMap a) {
        String label = field(a, A_LABEL);
        if (!label.isBlank()) return label;
        String s = field(a, A_STREET).trim(), c = field(a, A_CITY).trim();
        String joined = (s.isBlank() || c.isBlank()) ? (s + c) : (s + ", " + c);
        return joined.isBlank() ? "Address" : joined;
    }

    private void onAddAddress() {
        selectedAddress = null;
        addrLabel.setText("");
        addrStreet.setText("");
        addrCity.setText("");
        addrRegion.setText("");
        addrPostCode.setText("");
        addrCountry.setSelectedIndex(-1);
        profileCards.show("editAddress");

    }

    private void onRemoveAddress(NVGenericMap addr) {
        int ok = JOptionPane.showConfirmDialog(this,
                "Delete this address? This permanently removes it.",
                "Delete address", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;
        BackgroundTask.runCatching(this, null,
                () -> ctx.session().deleteAddress(addr),
                () -> {
                    addressSection.refresh();
                    JOptionPane.showMessageDialog(this, "Successfully deleted address");
                });
    }

    /**
     * The address detail card (fields + Save), reached by "+ Add address" or a per-row Edit.
     */
    private JPanel buildEditAddress() {
        JButton save = new JButton("Save address", new IconUtil.SaveIcon(16));
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
    private void onEditAddress(NVGenericMap address) {
        selectedAddress = address;
        addrLabel.setText(field(address, A_LABEL));
        addrStreet.setText(field(address, A_STREET));
        addrCity.setText(field(address, A_CITY));
        addrRegion.setText(field(address, A_STATE));
        addrPostCode.setText(field(address, A_POSTAL));
        String country = field(address, A_COUNTRY);
        if (country.isBlank()) addrCountry.setSelectedIndex(-1);
        else addrCountry.setSelectedItem(country);
        profileCards.show("editAddress");
    }


    private void onSaveAddress(JButton save) {
        // Require at least a label or street so we don't store an empty "Address" row.
        if (addrLabel.getText().isBlank() && addrStreet.getText().isBlank()) {
            JOptionPane.showMessageDialog(this,
                    "Enter at least a label or a street before saving.",
                    "Missing information", JOptionPane.WARNING_MESSAGE);
            return;
        }

        NVGenericMap target = (selectedAddress != null) ? selectedAddress : new NVGenericMap();
        Object country = addrCountry.getSelectedItem();
        target.build(A_LABEL, addrLabel.getText())
                .build(A_STREET, addrStreet.getText())
                .build(A_CITY, addrCity.getText())
                .build(A_STATE, addrRegion.getText())
                .build(A_POSTAL, addrPostCode.getText())
                .build(A_COUNTRY, country == null ? "" : country.toString());

        boolean isNew = (selectedAddress == null);
        BackgroundTask.runCatching(this, save,
                () -> {
                    if (isNew) {
                        ctx.session().addAddress(target);
                    } else {
                        ctx.session().changeAddressDetails(target);
                    }
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

        passwordSection = ListSection.of(() -> Arrays.stream(ctx.session().getAllCredentialForUserByType(CredentialInfo.Type.PASSWORD)).map(CIPassword.class::cast).toList())
                .title("Password")
                .label(_ -> "Password")
                .onEdit(_ -> () -> credentialCards.show("changePassword"))
                .build();

        apiKeySection = ListSection.of(() -> Arrays.stream(ctx.session().getAllCredentialForUserByType(CredentialInfo.Type.API_KEY)).map(SubjectAPIKey.class::cast).toList())
                .title("API keys")
                .addButton("+ Add API Key", this::onAddAPIKey)
                .label(p -> {
                    String label = p.getName();
                    return (label == null || label.isBlank()) ? "API key" : "API key — " + label;
                })
                .onEdit(p -> () -> onEditAPIKey(p))
                .onRemove(p -> () -> onDeleteAPIKey(p))
                .emptyText("No api keys yet")
                .build();

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

    // ============================ Add API key ============================

    private void onAddAPIKey() {

        APIKey<String> generated;
        try {
            generated = ctx.session().generateAPIKey();
        } catch (SecurityException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // --- Generate card: label + read-only (copyable) key + Copy ---
        JTextField genLabel = textField("e.g Claude prod");
        JTextField genDescription = textField("What this key is for");
        JTextField genKey = new JTextField(generated.getAPIKey(), 28);
        genKey.setEditable(false);               // selectable + copyable, not editable
        JButton copy = GUIUtil.iconButton(new IconUtil.CopyIcon(16));
        copy.setToolTipText("Copy");
        copy.addActionListener(_ -> {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(genKey.getText()), null);
            copy.setIcon(new IconUtil.SaveIcon(16));
            copy.setToolTipText("Copied!");
        });
        JButton refresh = GUIUtil.iconButton(new IconUtil.RefreshIcon(16));
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
            // new key → the old "Copied!" state no longer applies
            copy.setIcon(new IconUtil.CopyIcon(16));
            copy.setToolTipText("Copy");
        });
        JPanel copyRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        copyRow.add(genKey);
        copyRow.add(refresh);
        copyRow.add(copy);

        JPanel generateCard = new JPanel(new MigLayout(
                "wrap 2, insets 12, gapx 10, gapy 6",
                "[left][grow,fill]"
        ));

        addSection(generateCard, "Key");
        addRow(generateCard, "Label", genLabel);
        addRow(generateCard, "Description", genDescription);
        addRow(generateCard, "API Key", copyRow);

        // --- Enter-existing card: label + paste field ---
        JTextField inLabel = textField("e.g. Claude prod");
        JTextField inDescription = textField("What this key is for");
        JTextField inAppID = textField("e.g. nosneak");
        JTextField inDomainID = textField("e.g. xlogistx.io");
        JPasswordField inKey = new JPasswordField(28);
        inKey.putClientProperty("JTextField.placeholderText", "Your API key");
        JComboBox<String> inProvider = new JComboBox<>(new String[]{"Claude", "OpenAI", "Gemini"});
        inProvider.setEditable(true);
        inProvider.setSelectedItem(null);
        JTextField inBaseURI = textField("e.g. https://api.anthropic.com");
        JTextField inAuthScheme = textField("e.g. Bearer Token");
        JTextField inHeaderName = textField("e.g. x-api-key");

        JPanel inputCard = new JPanel(new MigLayout(
                "wrap 2, insets 12, gapx 10, gapy 6",
                "[left][grow,fill]"));

        addSection(inputCard, "Key");
        addRow(inputCard, "Label*", inLabel);
        addRow(inputCard, "Description*", inDescription);
        addRow(inputCard, "API Key*", PanelBuilder.passwordField(inKey));

        addSection(inputCard, "Scope");
        addRow(inputCard, "App ID", inAppID);
        addRow(inputCard, "Domain ID", inDomainID);

        addSection(inputCard, "Provider endpoint");
        addRow(inputCard, "Provider", inProvider);
        addRow(inputCard, "Base URL", inBaseURI);
        //addRow(inputCard, "API auth Type", inAuthScheme);
        //addRow(inputCard, "Header Name", inHeaderName);


        // --- selector + cards ---
        CardStack cards = new CardStack();
        cards.add(generateCard, "generate");
        cards.add(inputCard, "input");
        cards.show("input");

        //JToggleButton generateButton = new JToggleButton("Generate local key", true);
        JToggleButton existingButton = new JToggleButton("Add third party key");
        ButtonGroup selector = new ButtonGroup();
        //selector.add(generateButton);
        selector.add(existingButton);
        //generateButton.addActionListener(_ -> cards.show("generate"));
        existingButton.addActionListener(_ -> cards.show("input"));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
        //buttons.add(generateButton);
        buttons.add(existingButton);

        JPanel dialog = PanelBuilder.buildJPanelWithFields(
                PanelBuilder.title("Generate or Add Your API Key"),
                buttons, cards.view());

        String[] actions = {"Create key", "Cancel"};
        int result = JOptionPane.showOptionDialog(this, dialog, "Add API key",
                JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, actions, actions[0]);
        if (result != 0) return;   // Cancel or dialog closed

        boolean generating = false; //generateButton.isSelected();
        String label = generating ? genLabel.getText() : inLabel.getText();
        String description = generating ? genDescription.getText() : inDescription.getText();
        String appId = generating ? "" : inAppID.getText().trim();
        String domainId = generating ? "" : inDomainID.getText().trim();
        String key = generating ? genKey.getText() : new String(inKey.getPassword()).trim();
        String provider = generating ? "" : Objects.toString(inProvider.getSelectedItem(), "").trim();
        String baseURI = generating ? "" : inBaseURI.getText().trim();
        String authScheme = generating ? "" : inAuthScheme.getText().trim();
        String headerName = generating ? "" : inHeaderName.getText().trim();

        // An external (third party) key requires both the AppID and the key.
        if (!generating && (appId.isBlank() || key.isBlank())) {
            JOptionPane.showMessageDialog(this,
                    "Enter both the App Id and the key to add a third party API key.",
                    "Missing information", JOptionPane.WARNING_MESSAGE);
            return;
        }

        BackgroundTask.runCatching(this, null,
                () -> ctx.session().storeAPIKey(label, description, domainId, appId, key, provider, baseURI, authScheme, headerName, !generating),
                () -> {
                    passwordSection.refresh();
                    apiKeySection.refresh();
                    JOptionPane.showMessageDialog(this, "API key added.");
                });
    }


    // ============================ Change password ============================

    private JPanel buildChangePassword() {
        JButton submit = new JButton("Change password", new IconUtil.SaveIcon(16));
        submit.addActionListener(_ -> onChangePassword(submit));

        return PanelBuilder.detail("Change password",
                () -> credentialCards.show("list"),
                panel -> {
                    panel.add(new JLabel("Current password"));
                    panel.add(PanelBuilder.passwordField(currentPwd));
                    panel.add(new JLabel("New password"));
                    panel.add(PanelBuilder.passwordField(newPwd));
                    panel.add(new JLabel("Confirm new password"));
                    panel.add(PanelBuilder.passwordField(confirmPwd));
                    panel.add(submit);
                });
    }

    private void onChangePassword(JButton submit) {
        char[] cur = currentPwd.getPassword();
        char[] next = newPwd.getPassword();

        if (!Arrays.equals(next, confirmPwd.getPassword())) {
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

        // save api key button
        JButton submit = GUIUtil.iconButton(new IconUtil.SaveIcon(16));
        submit.setToolTipText("Save");

        rotateKey.setToolTipText("Rotate");
        rotateKey.addActionListener(_ -> onRotateAPIKey(rotateKey));

        // copy api key button
        JButton copyKey = GUIUtil.iconButton(new IconUtil.CopyIcon(16));
        copyKey.setToolTipText("Copy");
        submit.addActionListener(_ -> onEditAPIDetails(submit));
        copyKey.addActionListener(_ -> {
            if (selectedKey != null && selectedKey.getAPIKey() != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(selectedKey.getAPIKey()), null);
            }
        });

        // Toggle: masking is currently on when isKeyShown is false, so flip it.
        showKey.addActionListener(_ -> setKeyMasked(isKeyShown));

        editKeySecret.setEditable(false);
        keyAppID.setEditable(true);
        keyDomainID.setEditable(true);
        keyProvider.setEditable(true);
        keyURI.setEditable(true);

        JPanel keyView = new JPanel(new FlowLayout(FlowLayout.LEFT));

        keyView.add(editKeySecret);
        keyView.add(rotateKey);
        keyView.add(copyKey);
        keyView.add(showKey);
        keyView.add(submit);

        return PanelBuilder.detail("Edit API key",
                () -> credentialCards.show("list"),
                panel -> {


                    panel.add(new JLabel("Label"));
                    panel.add(editKeyLabel);

                    panel.add(new JLabel("Description"));
                    panel.add(editKeyDescription);

                    panel.add(new JLabel("App ID"));
                    panel.add(keyAppID);

                    panel.add(new JLabel("Domain ID"));
                    panel.add(keyDomainID);

                    panel.add(new JLabel("Provider"));
                    panel.add(keyProvider);

                    panel.add(new JLabel("Base URI"));
                    panel.add(keyURI);

                    panel.add(new JLabel("API Key"));
                    panel.add(keyView);
                }
        );
    }

    private void onEditAPIKey(SubjectAPIKey key) {
        selectedKey = key;

        // External (third-party) keys aren't issued by us, so they can't be rotated.
        boolean external = ctx.session().isExternalKey(key);
        rotateKey.setEnabled(!external);
        rotateKey.setToolTipText(external ? "External keys can't be rotated" : "Rotate");

        editKeySecret.setText(key.getAPIKey());
        editKeySecret.setCaretPosition(0);
        setKeyMasked(true);   // every key opens hidden, regardless of the previous selection
        editKeyLabel.setText(key.getName());
        editKeyDescription.setText(key.getDescription());

        if (key.getAppID() != null) {
            keyAppID.setText(key.getAppID().getAppID());
            keyDomainID.setText(key.getAppID().getDomainID());
        } else {
            keyAppID.setText("");
            keyDomainID.setText("");
        }

        String provider = ctx.session().providerOf(key);
        String baseUrl = ctx.session().baseUrlOf(key);
        String scheme = ctx.session().authTypeOf(key);
        String header = ctx.session().headerNameOf(key);
        keyProvider.setText(provider == null ? "" : provider);
        keyURI.setText(baseUrl == null ? "" : baseUrl);
        authScheme.setText(scheme == null ? "" : scheme);
        headerName.setText(header == null ? "" : header);

        credentialCards.show("editAPI");
    }

    private void setKeyMasked(boolean masked) {
        editKeySecret.setEchoChar(masked ? defaultEcho : (char) 0);
        showKey.setIcon(masked ? new IconUtil.VisibleIcon(16) : new IconUtil.InvisibleIcon(16));
        showKey.setToolTipText(masked ? "Show" : "Hide");
        isKeyShown = !masked;
    }

    private void onEditAPIDetails(JButton submit) {
        String label = editKeyLabel.getText().trim();
        String description = editKeyDescription.getText().trim();

        if (label.isBlank() || description.isBlank()) {
            JOptionPane.showMessageDialog(this,
                    "Label and description are required.",
                    "Missing information", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String appID = keyAppID.getText().trim();
        String domainID = keyDomainID.getText().trim();
        String provider = keyProvider.getText();
        String uri = keyURI.getText();
        String scheme = authScheme.getText();
        String header = headerName.getText();

        BackgroundTask.runCatching(this, submit,
                () -> ctx.session().changeAPIDetails(selectedKey, label, description, domainID, appID,
                        provider, uri, scheme, header),
                () -> {
                    JOptionPane.showMessageDialog(this, "API Key updated");
                    selectedKey = null;
                    editKeySecret.setText("");
                    editKeyLabel.setText("");
                    editKeyDescription.setText("");
                    keyAppID.setText("");
                    keyDomainID.setText("");
                    keyProvider.setText("");
                    keyURI.setText("");
                    authScheme.setText("");
                    headerName.setText("");
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
                    onEditAPIKey(selectedKey);
                    apiKeySection.refresh();
                    JOptionPane.showMessageDialog(this, "Key rotated. Copy the new secret now.");
                });
    }

    private void onDeleteAPIKey(SubjectAPIKey key) {
        if (key == null) return;
        int ok = JOptionPane.showConfirmDialog(this,
                "Delete this key? This permanently removes it.",
                "Delete API key", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        BackgroundTask.runCatching(this, null,
                () -> ctx.session().deleteAPIKey(key),
                () -> {
                    apiKeySection.refresh();
                    JOptionPane.showMessageDialog(this, "API key Deleted.");
                });
    }
}
