package io.xlogistx.nosneak.app.ui;

import io.xlogistx.datastore.h2p.H2PDataStore;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.WrapLabel;
import io.xlogistx.gui.*;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.ui.utility.*;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.data.DataConst;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.PrincipalIdentifier;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVPair;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.text.NumberFormat;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

import static io.xlogistx.gui.PanelBuilder.*;

public class SubjectPanel extends JPanel {

    /** A copied API-key secret is wiped from the clipboard after this long, if it is still there. */
    static final int SECRET_CLIPBOARD_MILLIS = 60_000;
    private static final String COPIED_TIP = "Copied (cleared from the clipboard after 60 s)";

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
    private final JPasswordField currentPwd = new JPasswordField(35);
    private final JPasswordField newPwd = new JPasswordField(35);
    private final JPasswordField confirmPwd = new JPasswordField(35);

    // ---- Edit-API-key fields (populated from whichever key the user clicks in the list) ----
    private final JPasswordField editKeySecret = new JPasswordField(30);
    private final JTextField editKeyLabel = new JTextField(20);
    private final JTextField editKeyDescription = new JTextField(20);
    private final JTextField keyAppID = new JTextField(20);
    private final JTextField keyDomainID = new JTextField(20);
    private final JComboBox<String> keyProvider = new JComboBox<>(PROVIDER_DISPLAY);
    private final JTextField keyURI = new JTextField(20);
    private final JTextField authScheme = new JTextField(20);
    private final JTextField headerName = new JTextField(20);
    private SubjectAPIKey selectedKey;
    private boolean isKeyShown = false;
    private final char defaultEcho = editKeySecret.getEchoChar();
    private final JButton showKey = GUIUtil.iconButton(new IconUtil.VisibleIcon(16));
    private final JButton rotateKey = GUIUtil.iconButton(new IconUtil.RefreshIcon(16));

    // ---- Edit-address fields (populated from the clicked address; null selection = new address) ----
    private final JTextField addrLabel = new JTextField(35);
    private final JTextField addrStreet = new JTextField(35);
    private final JTextField addrCity = new JTextField(35);
    private final JTextField addrRegion = new JTextField(35);
    private final JTextField addrPostCode = new JTextField(35);
    private final String[] countries = DataConst.COUNTRIES.getValue().stream()
            .map(NVPair::getValue)
            .toArray(String[]::new);
    private final JComboBox<String> addrCountry = new JComboBox<>(countries);
    private NVGenericMap selectedAddress;

    // Field keys for an address map (stored inline in the subject's property bag)
    private static final String A_LABEL = "label", A_STREET = "street", A_CITY = "city",
            A_STATE = "state", A_POSTAL = "postal", A_COUNTRY = "country";

    private static final String[] PROVIDER_DISPLAY = {"OpenAI", "Anthropic (Claude)", "Google (Gemini)", "Grok (xAI)"};
    private final JComboBox<String> inProvider = new JComboBox<>(PROVIDER_DISPLAY);

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

        // Phase 5 of the redesign (2026-10-24): Profile and Settings sit in the shared page frame;
        // Credentials already has its own two-card layout (Phase 4). Backup and Restore are
        // blocks of the Settings page since 2026-10-26 (they had a page of their own before).
        PagePanel profilePage = new PagePanel(Navigator.Screen.PROFILE.getDisplayName(), "Your account: name, date of birth, identifiers and addresses.");
        profilePage.card(scroll(buildProfileArea()));
        cardStack.add(profilePage, "Profile");
        cardStack.add(buildCredentials(), "Credentials");
        PagePanel settingsPage = new PagePanel(Navigator.Screen.SETTINGS.getDisplayName(), "Reference data this installation keeps up to date, and the store's backup.");
        settingsPage.card(scroll(buildSettingsArea()));
        cardStack.add(settingsPage, SECTION_SETTINGS);
        cardStack.show(SECTION_PROFILE);

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
                cardStack.show(SECTION_PROFILE);
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
                keyProvider.setSelectedItem(null);
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

        // API keys can also be created and deleted from the AI assistant's Providers page, so the
        // credential rows refresh on the session's credentials event, not only on this panel's
        // own mutations. Fired off the EDT — hop before touching Swing.
        ctx.session().onMacVendorsChange(_ -> SwingUtilities.invokeLater(this::refreshSyncStatus));
        ctx.session().onCredentialsChange(_ -> SwingUtilities.invokeLater(() -> {
            passwordSection.refresh();
            apiKeySection.refresh();
        }));

        add(cardStack.view(), BorderLayout.CENTER);
    }

    /** A borderless scroll pane on the surface colour, for a card's content. */
    private static JScrollPane scroll(JComponent content) {
        content.setOpaque(true);
        content.setBackground(UITokens.surface());
        content.setBorder(BorderFactory.createEmptyBorder(12, 16, 16, 16));
        JScrollPane sp = new JScrollPane(content, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.getViewport().setBackground(UITokens.surface());
        sp.getVerticalScrollBar().setUnitIncrement(16);
        return sp;
    }

    /** The sections the application's sidebar routes to (2026-10-24); the toggle column is gone. */
    public static final String SECTION_PROFILE = "Profile";
    public static final String SECTION_CREDENTIALS = "Credentials";
    public static final String SECTION_SETTINGS = "Settings";

    /** Shows one of the {@code SECTION_*} cards. */
    public void show(String section) {
        cardStack.show(section);
        if (SECTION_SETTINGS.equals(section)) refreshSyncStatus();
    }

    // ============================ Settings ============================

    private final JLabel syncStatus = new JLabel(" ");

    private JPanel buildSettingsArea() {
        JPanel area = new JPanel(new MigLayout("wrap 1, insets 0", "[grow,fill]"));
        area.add(buildSync());
        area.add(new JSeparator(), "gaptop 8, gapbottom 8");
        area.add(buildDBBackup());
        area.add(new JSeparator(), "gaptop 8, gapbottom 8");
        area.add(buildDBRestore());

        JPanel anchor = new JPanel(new BorderLayout());
        anchor.add(area, BorderLayout.NORTH);
        return anchor;
    }

    /**
     * The Sync section (2026-10-25): the MAC vendor list is downloaded at the first sign-in and
     * kept in the store for every account; this replaces it with the current one on demand
     * ({@link Session#syncMacVendors}). Its status line is the same text as the status bar's
     * (2026-10-27): re-read when the page is shown and whenever {@link Session#onMacVendorsChange}
     * says the table was filled — by the post-login load or a sync — so it never shows a stale state.
     */
    private JPanel buildSync() {
        JPanel panel = new JPanel(new MigLayout("wrap 1, insets 12, gapy 6", "[grow,fill]"));

        panel.add(PanelBuilder.title("Sync"));

        // WrapLabel, not a wrapping JTextArea: its height is computed at the wrap width, so the
        // block does not come out too tall on first show (the Phase 1 lesson)
        WrapLabel note = new WrapLabel("""
                MAC vendors — the Wireshark manufacturer list (wireshark.org, manuf) names the vendor \
                of each host's network adapter in scan reports: the MAC and Vendor columns of the Hosts \
                tab and the Network adapter block of the host detail. It is downloaded once at the \
                first sign-in and kept in this store for every account; the status bar at the bottom \
                of the window shows its state.

                Sync downloads the current list and replaces the stored copy. Wireshark publishes a \
                new one about once a week.""");
        note.setWrapWidth(480);
        note.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        panel.add(note, "growx 0");

        JButton sync = new JButton("Sync MAC vendors",
                IconUtil.svgIcon("io/xlogistx/gui/icons/refresh.svg", 16, UITokens.text()));
        syncStatus.setForeground(UITokens.muted());

        sync.addActionListener(_ -> onSyncMacVendors(sync));
        panel.add(sync, "growx 0");
        panel.add(syncStatus);

        return panel;
    }

    /** The "last sync" day in the status line says it was synced; the event-driven refresh shows it. */
    private void onSyncMacVendors(JButton sync) {
        syncStatus.setText("Downloading the vendor list…");
        BackgroundTask.run(this, sync, () -> {
            try {
                return ctx.session().syncMacVendors();
            } catch (IOException e) {
                throw new AccessSecurityException("Could not download the vendor list from wireshark.org: " + e.getMessage(), e);
            }
        }, status -> syncStatus.setText(syncStatusText(status)));
    }

    /**
     * Re-reads the stored list's timestamps off the EDT and shows them; "loading" while the
     * post-login load is still filling the table (the login screen waits for it, so this is rare).
     */
    private void refreshSyncStatus() {
        if (!ctx.session().isAuthenticated()) {
            syncStatus.setText(" ");
            return;
        }
        if (!ctx.session().macVendorsLoaded()) {
            syncStatus.setText("Loading the vendor list…");
            return;
        }
        BackgroundTask.run(this, null, () -> ctx.session().macVendorStatus(), status -> syncStatus.setText(syncStatusText(status)));
    }

    static String syncStatusText(Session.MacVendorStatus status) {
        if (!status.stored()) return "No stored list yet — it is downloaded at sign-in, or sync now.";
        StringBuilder sb = new StringBuilder();
        sb.append(NumberFormat.getIntegerInstance(Locale.US).format(status.entries())).append(" vendors loaded · stored ")
                .append(day(status.storedTs()));
        if (status.syncedTs() > status.storedTs()) sb.append(" · last sync ").append(day(status.syncedTs()));
        return sb.toString();
    }

    private static String day(long epochMs) {
        return LocalDate.ofInstant(Instant.ofEpochMilli(epochMs), ZoneId.systemDefault()).toString();
    }

    // ==================== Backup and Restore (Settings blocks) ====================

    private static final String[] RESTORE_MODES = {"Merge into this store", "Replace this store"};

    /** A block's note: a WrapLabel at the Sync block's width (its height is right on first show). */
    private static WrapLabel blockNote(String text) {
        WrapLabel note = new WrapLabel(text);
        note.setWrapWidth(480);
        note.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        return note;
    }

    /** A block's muted status line. */
    private static JLabel blockStatus() {
        JLabel status = new JLabel(" ");
        status.setForeground(UITokens.muted());
        return status;
    }

    /**
     * The Restore block (2026-10-26; note and status in the Sync block's shape since 2026-10-27):
     * loads a backup archive into the store in Merge or Replace mode and signs the subject out.
     */
    private JPanel buildDBRestore() {
        JPanel panel = new JPanel(new MigLayout("wrap 1, insets 12, gapy 6", "[grow,fill]"));

        panel.add(PanelBuilder.title("Restore"));
        panel.add(blockNote("""
                Loads a backup archive back into this store: accounts and their API keys, scan reports, \
                chats, captures, skills, probes and the MAC vendor list, all under the accounts that \
                owned them. The vault is not touched; sealed values in the archive open only with the \
                vault they were exported under.

                Merge keeps what is already here and adds or overwrites records from the archive. \
                Replace clears the store first, so it ends up holding exactly what the archive holds.

                You are signed out when the restore finishes — the account you are signed in as may \
                have been rewritten or removed by it. Sign in again to carry on."""), "growx 0");

        JComboBox<String> mode = new JComboBox<>(RESTORE_MODES);
        JButton restore = new JButton("Restore backup", new IconUtil.RollbackIcon(16));
        JLabel status = blockStatus();

        restore.addActionListener(_ -> onRestoreBackup(restore, status, mode.getSelectedIndex()));
        panel.add(mode, "growx 0, width 240!");
        panel.add(restore, "growx 0");
        panel.add(status);

        return panel;
    }

    private void onRestoreBackup(JButton restore, JLabel status, int modeIndex) {
        if (!(ctx.session().getDomainSecurityManager().getDataStore() instanceof H2PDataStore ds)) {
            JOptionPane.showMessageDialog(this, "This data store cannot be restored.",
                    "Restore", JOptionPane.ERROR_MESSAGE);
            return;
        }

        H2PDataStore.RestoreMode mode = modeIndex == 1
                ? H2PDataStore.RestoreMode.WIPE_AND_LOAD
                : H2PDataStore.RestoreMode.MERGE;

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Restore backup");
        chooser.setCurrentDirectory(AppPrefs.fileDirectory());
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File source = chooser.getSelectedFile();
        AppPrefs.fileDirectory(source);
        String warning = mode == H2PDataStore.RestoreMode.WIPE_AND_LOAD
                ? "Every record in this store will be deleted and replaced with the contents of\n"
                + source.getName() + ".\n\nThis cannot be undone. Continue?"
                : "Records from " + source.getName() + " will be added to this store, overwriting\n"
                + "any that share the same id.\n\nContinue?";

        if (JOptionPane.showConfirmDialog(this, warning, "Restore backup",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.OK_OPTION) {
            return;
        }

        status.setText("Restoring…");
        BackgroundTask.run(this, restore,
                // a whole-store restore needs the store's system context, not a subject
                () -> ctx.session().runAsSystem(() -> {
                    try (InputStream in = new BufferedInputStream(new FileInputStream(source))) {
                        return ds.restore(in, mode);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }),
                _ -> {
                    status.setText("Restored " + source.getName());
                    ctx.session().logout();
                    JOptionPane.showMessageDialog(this,
                            "Restore complete. You have been signed out — sign in again to use the "
                                    + "restored data.");
                });
    }

    /**
     * The Backup block (2026-10-26; note and status in the Sync block's shape since 2026-10-27):
     * dumps the whole store to a zip archive named after the store and the day.
     */
    private JPanel buildDBBackup() {
        JPanel panel = new JPanel(new MigLayout("wrap 1, insets 12, gapy 6", "[grow,fill]"));

        panel.add(PanelBuilder.title("Backup"));
        panel.add(blockNote("""
                Exports every record in this store — accounts and their API keys, scan reports, chats, \
                captures, skills, probes and the MAC vendor list — as one zip archive.

                The archive itself is not encrypted; the sealed values in it (API keys and other \
                secrets) can only be opened again with this installation's vault, so keep the file \
                somewhere you would keep the vault, and keep the vault. Scan reports in it carry \
                your network's layout, so treat it as sensitive."""), "growx 0");

        JButton export = new JButton("Export backup", new IconUtil.SaveIcon(16));
        JLabel status = blockStatus();

        export.addActionListener(_ -> onExportBackup(export, status));
        panel.add(export, "growx 0");
        panel.add(status);

        return panel;
    }

    private void onExportBackup(JButton export, JLabel status) {
        if (!(ctx.session().getDomainSecurityManager().getDataStore() instanceof H2PDataStore ds)) {
            JOptionPane.showMessageDialog(this, "This data store cannot be exported.",
                    "Backup", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export backup");
        chooser.setCurrentDirectory(AppPrefs.fileDirectory());
        chooser.setSelectedFile(new File(NoSneakMain.dbName + "-backup-" + LocalDate.now() + ".zip"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File target = chooser.getSelectedFile();
        AppPrefs.fileDirectory(target);
        if (target.exists() && JOptionPane.showConfirmDialog(this,
                target.getName() + " already exists. Replace it?", "Export backup",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.OK_OPTION) {
            return;
        }

        status.setText("Exporting…");
        BackgroundTask.run(this, export,
                // a whole-store dump needs the store's system context, not a subject
                () -> ctx.session().runAsSystem(() -> {
                    try (OutputStream out = new BufferedOutputStream(new FileOutputStream(target))) {
                        ds.dumpZip(out);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                    return target.length();
                }),
                size -> {
                    status.setText("Exported " + target.getName() + " — " + (size / 1024) + " KB");
                    JOptionPane.showMessageDialog(this, "Backup written to\n" + target.getAbsolutePath());
                });
    }

    // ============================ Profile & identifiers ============================

    /** The Profile page's content: the profile card or the address detail, both 480 px wide like the Settings blocks. */
    private JPanel buildProfileArea() {
        profileCards.add(buildProfile(), "profile");
        profileCards.add(buildEditAddress(), "editAddress");
        profileCards.show("profile");

        JPanel anchor = new JPanel(new MigLayout("insets 0", "[480!]"));
        anchor.setOpaque(false);
        anchor.add(profileCards.view(), "growx, aligny top");
        JPanel p = new JPanel(new BorderLayout());
        p.setOpaque(false);
        p.add(anchor, BorderLayout.NORTH);
        return p;
    }

    private final JLabel profileStatus = blockStatus();

    /**
     * The profile card (re-laid out 2026-10-27 in the Settings page's shape): three blocks
     * separated by rules — <b>Name</b> (a {@link FormPanel} with the page's one primary action,
     * Save changes, and a status line instead of a dialog), <b>Identifiers</b> and
     * <b>Addresses</b> (the two {@link ListSection}s, each with a description of what the list
     * is for).
     */
    private JPanel buildProfile() {
        identifiers = ListSection.of(() -> ctx.session().getAllPrincipalIDForLoggedInUser())
                .title("Identifiers")
                .description("The names you can sign in with: usernames and email addresses. Deleting the one "
                        + "you signed in with moves your account to another of them.")
                .addButton("+ Add identifier", this::onAddIdentifier)
                .label(PrincipalIdentifier::getPrincipalID)
                .onRemove(p -> () -> onRemoveIdentifier(p))
                .build();

        addressSection = ListSection.of(() -> ctx.session().getAllAddresses())
                .title("Addresses")
                .description("Postal addresses kept with your account, for your own records; nothing reads them.")
                .addButton("+ Add address", this::onAddAddress)
                .label(this::addressLabel)
                .onEdit(p -> () -> onEditAddress(p))
                .onRemove(p -> () -> onRemoveAddress(p))
                .emptyText("No addresses yet")
                .build();

        FormPanel form = new FormPanel();
        form.field("First name", firstName);
        form.field("Last name", lastName);
        form.field("Date of birth", dob, "Optional, as yyyy-mm-dd.");
        saveProfile.setText("Save changes");
        UITokens.primary(saveProfile);
        saveProfile.addActionListener(_ -> onSaveProfile());

        JPanel name = new JPanel(new MigLayout("wrap 1, insets 12, gapy 6", "[grow,fill]"));
        name.setOpaque(false);
        name.add(PanelBuilder.title("Name"));
        name.add(blockNote("How the account is shown; kept in this store under your account and nowhere else."), "growx 0");
        name.add(form, "growx");
        name.add(saveProfile, "growx 0, gaptop 10");
        name.add(profileStatus);

        JPanel card = new JPanel(new MigLayout("wrap 1, insets 0", "[grow,fill]"));
        card.setOpaque(false);
        card.add(name);
        card.add(new JSeparator(), "gaptop 8, gapbottom 8");
        card.add(identifiers, "gapx 12 12");
        card.add(new JSeparator(), "gaptop 16, gapbottom 8");
        card.add(addressSection, "gapx 12 12, gapbottom 12");
        return card;
    }

    private void onSaveProfile() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("firstName", firstName.getText());
        fields.put("lastName", lastName.getText());
        fields.put("dob", dob.getText());
        profileStatus.setText("Saving…");
        BackgroundTask.runCatching(this, saveProfile,
                () -> ctx.session().saveProfile(fields),
                () -> profileStatus.setText("Saved."));
    }

    private void populateProfile() {
        Map<String, String> p = ctx.session().loadProfile(PROFILE_KEYS);
        firstName.setText(p.get("firstName"));
        lastName.setText(p.get("lastName"));
        dob.setText(p.get("dob"));
    }

    private void onAddIdentifier() {
        JComboBox<String> kind = new JComboBox<>(new String[]{"Email", "Username"});
        JTextField value = new JTextField(24);
        JPanel form = new JPanel(new MigLayout("wrap 2, insets 8, gapx 10, gapy 6", "[left][grow,fill]"));
        addRow(form, "Kind", kind);
        addRow(form, "Value", value);

        int ok = JOptionPane.showConfirmDialog(this, form, "Add identifier",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        String id = value.getText().trim();
        if (id.isEmpty()) return;
        if ("Email".equals(kind.getSelectedItem()) && !FilterType.EMAIL.isValid(id)) {
            JOptionPane.showMessageDialog(this, "Enter a valid email address.",
                    "Invalid email", JOptionPane.WARNING_MESSAGE);
            return;
        }
        BackgroundTask.runCatching(this, null,
                () -> ctx.session().addIdentifier(id),
                () -> identifiers.refresh());
    }

    private static String deleteConfirm(String name, String noun) {
        String subject = (name == null || name.isBlank()) ? "this " + noun : "'" + name + "'";
        return "Delete " + subject + "? This permanently removes it.";
    }

    private void onRemoveIdentifier(PrincipalIdentifier p) {
        int ok = JOptionPane.showConfirmDialog(this,
                deleteConfirm(p.getPrincipalID(), "identifier"), "Delete identifier",
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
                deleteConfirm(addressLabel(addr), "address"),
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
        JButton save = UITokens.primary(new JButton("Save address", new IconUtil.SaveIcon(16)));
        save.addActionListener(_ -> onSaveAddress(save));

        // the same stacked form as the Name block (2026-10-27); Back returns to the profile card
        FormPanel form = new FormPanel();
        form.field("Label", addrLabel, "A name for it: Home, Work…");
        form.field("Street", addrStreet);
        form.field("City", addrCity);
        form.field("State / region", addrRegion);
        form.field("Postal code", addrPostCode);
        form.field("Country", addrCountry);

        return PanelBuilder.detail("Address",
                () -> profileCards.show("profile"),
                panel -> {
                    panel.add(blockNote("A label or a street is enough to save it."), "growx, wmin 0");
                    panel.add(form, "growx, wmin 0");
                    panel.add(save, "gaptop 12");
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

    /**
     * The API keys page (board 5 of the redesign canvas, 2026-10-24): the credential list on the
     * left, the editor on the right. The right-hand stack keeps the old card names — {@code "list"}
     * is now the placeholder shown while nothing is being edited — so every
     * {@code credentialCards.show("list")} after a save, a delete or a logout still lands on the
     * right thing without touching those call sites.
     */
    private JPanel buildCredentials() {
        JLabel placeholder = new JLabel("Select a key to edit it, or add one.", SwingConstants.CENTER);
        placeholder.setForeground(UITokens.muted());
        JPanel empty = new JPanel(new BorderLayout());
        empty.setOpaque(false);
        empty.add(placeholder, BorderLayout.CENTER);

        credentialCards.add(empty, "list");
        credentialCards.add(buildChangePassword(), "changePassword");
        credentialCards.add(buildEditAPIKey(), "editAPI");
        credentialCards.show("list");

        // 2026-10-27: the page frame of every other page (title, description, the one primary
        // action in the head — Add API key, which was a button inside the list), the two cards below
        JPanel left = buildCredentialList();
        left.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UITokens.border()),
                BorderFactory.createEmptyBorder(8, 8, 8, 8)));
        left.setBackground(UITokens.surface());
        JPanel right = new JPanel(new BorderLayout());
        right.setBackground(UITokens.surface());
        right.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        right.add(credentialCards.view(), BorderLayout.CENTER);

        JPanel split = new JPanel(new MigLayout("insets 0, gapx 20, fill", "[grow 45,fill][grow 55,fill]", "[grow,fill]"));
        split.setOpaque(false);
        split.add(left, "wmin 0, hmin 0, aligny top, growy");
        split.add(right, "wmin 0, hmin 0, aligny top, growy");

        PagePanel page = new PagePanel(Navigator.Screen.API_KEYS.getDisplayName(),
                "Your password, and the third-party API keys the assistant borrows; it holds none of its own.");
        JButton addKey = UITokens.primary(new JButton("Add API key", new IconUtil.PlusIcon(16)));
        addKey.addActionListener(_ -> onAddAPIKey());
        page.action(addKey);
        page.add(split, "grow, push");
        return page;
    }

    private JPanel buildCredentialList() {

        passwordSection = ListSection.of(() -> ctx.session().getAllCredentialForUserByType(CredentialInfo.Type.PASSWORD).stream().filter(CIPassword.class::isInstance).map(CIPassword.class::cast).toList())
                .title("Password")
                .description("The password you sign in with. The vault password is a different one and is not kept here.")
                .label(SubjectPanel::passwordLabel)
                .onEdit(_ -> () -> credentialCards.show("changePassword"))
                .build();

        apiKeySection = ListSection.of(() -> ctx.session().getAllCredentialForUserByType(CredentialInfo.Type.API_KEY).stream().filter(SubjectAPIKey.class::isInstance).map(SubjectAPIKey.class::cast).toList())
                .title("API keys")
                .description("Keys of third-party AI providers, kept sealed in this store under your account. "
                        + "The assistant's Providers page picks among them; a key is never sent anywhere but to its own provider.")
                .label(p -> {
                    String label = p.getName();
                    return (label == null || label.isBlank()) ? "API key" : "API key — " + label;
                })
                .onEdit(p -> () -> onEditAPIKey(p))
                .onRemove(p -> () -> onDeleteAPIKey(p))
                .emptyText("No API keys yet")
                .build();

        JPanel content = new JPanel(new MigLayout("wrap 1, insets 4, gapy 12", "[grow,fill]"));
        content.setOpaque(false);
        content.add(passwordSection);
        content.add(apiKeySection);

        JPanel p = new JPanel(new BorderLayout());
        p.setOpaque(false);
        p.add(content, BorderLayout.NORTH);   // hug the top; leftover space stays at the bottom
        return p;
    }

    static String passwordLabel(CIPassword p) {
        long ts = Math.max(p.getLastTimeUpdated(), p.getCreationTime());
        if (ts <= 0) return "Password — set";
        long days = (System.currentTimeMillis() - ts) / 86_400_000L;
        if (days <= 0) return "Password — set · changed today";
        return "Password — set · last changed " + days + (days == 1 ? " day ago" : " days ago");
    }

    // ============================ Add API key ============================

    private void onAddAPIKey() {

        APIKey<String> generated;
        try {
            generated = ctx.session().generateAPIKey();
        } catch (AccessSecurityException e) {
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
            GUIUtil.copyToClipboard(genKey.getText(), SECRET_CLIPBOARD_MILLIS);
            copy.setIcon(new IconUtil.CheckIcon(16));
            copy.setToolTipText(COPIED_TIP);
        });
        JButton refresh = GUIUtil.iconButton(new IconUtil.RefreshIcon(16));
        refresh.setToolTipText("Refresh");
        refresh.addActionListener(_ -> {
            APIKey<String> refreshed;
            try {
                refreshed = ctx.session().generateAPIKey();
            } catch (AccessSecurityException e) {
                JOptionPane.showMessageDialog(this, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            genKey.setText(refreshed.getAPIKey());
            // new key → the old "Copied" state no longer applies
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

        // --- Enter-existing card: the stacked form (2026-10-27), see newAddKeyForm ---
        AddKeyForm in = newAddKeyForm();

        // --- cards (the generate card stays registered for when local keys return) ---
        CardStack cards = new CardStack();
        cards.add(generateCard, "generate");
        cards.add(in.panel, "input");
        cards.show("input");

        String[] actions = {"Create key", "Cancel"};
        int result = JOptionPane.showOptionDialog(this, cards.view(), "Add API key",
                JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, actions, actions[0]);
        if (result != 0) return;   // Cancel or dialog closed

        boolean generating = false; //generateButton.isSelected();
        String label = generating ? genLabel.getText() : in.label.getText();
        String description = generating ? genDescription.getText() : in.description.getText();
        String appId = generating ? "" : in.appID.getText().trim();
        String domainId = generating ? "" : in.domainID.getText().trim();
        String key = generating ? genKey.getText() : new String(in.key.getPassword()).trim();
        String provider = generating ? "" : comboText(inProvider);
        String baseURI = generating ? "" : in.baseURI.getText().trim();
        String authScheme = generating ? "" : in.authScheme.getText().trim();
        String headerName = generating ? "" : in.headerName.getText().trim();

        if (!generating && (label.isBlank() || key.isBlank())) {
            JOptionPane.showMessageDialog(this,
                    "Label and API key are required.",
                    "Missing information", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (!generating && (appId.isBlank() != domainId.isBlank())) {
            JOptionPane.showMessageDialog(this,
                    "Provide both App ID and Domain ID, or leave both empty.",
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


    /** The add dialog's form and its fields (one object so the dialog and the render harness share it). */
    private static final class AddKeyForm {
        final JPanel panel;
        final JTextField label = textField("e.g. Claude prod");
        final JTextField description = textField("What this key is for");
        final JPasswordField key = new JPasswordField(28);
        final JTextField appID = textField("e.g. nosneak");
        final JTextField domainID = textField("e.g. xlogistx.io");
        final JTextField baseURI = textField("e.g. https://api.anthropic.com");
        final JTextField authScheme = textField("e.g. Bearer Token");
        final JTextField headerName = textField("e.g. x-api-key");

        AddKeyForm(JComboBox<String> provider) {
            key.putClientProperty("JTextField.placeholderText", "Your API key");
            FormPanel form = new FormPanel();
            form.row(PanelBuilder.title("Add a third-party API key"), "growx");
            form.row(blockNote("The key is sealed in this store under your account and sent only to its own provider."), "growx, wmin 0");
            form.row(PanelBuilder.sectionHeader("Key"), "growx, gaptop 10");
            form.requiredField("Label", label);
            form.field("Description", description);
            form.requiredField("API key", PanelBuilder.passwordField(key));
            form.row(PanelBuilder.sectionHeader("Scope"), "growx, gaptop 10");
            form.field("App ID", appID);
            form.field("Domain ID", domainID, "Both, or neither.");
            form.row(PanelBuilder.sectionHeader("Provider endpoint"), "growx, gaptop 10");
            form.field("Provider", provider, "Pick one, or type the name of another.");
            form.field("Base URL", baseURI);
            panel = new JPanel(new MigLayout("insets 12", "[480!]")); // the note's wrap width
            panel.setOpaque(false);
            panel.add(form, "growx");
        }
    }

    private AddKeyForm newAddKeyForm() {
        inProvider.setEditable(true);
        inProvider.setSelectedItem(null);
        if (inProvider.getEditor().getEditorComponent() instanceof JTextField providerEditor) {
            providerEditor.putClientProperty("JTextField.placeholderText", "Select or type a provider");
        }
        return new AddKeyForm(inProvider);
    }

    // ============================ Change password ============================

    /** The change-password card (the stacked form since 2026-10-27; Back returns to the placeholder). */
    private JPanel buildChangePassword() {
        JButton submit = UITokens.primary(new JButton("Change password", new IconUtil.SaveIcon(16)));
        submit.addActionListener(_ -> onChangePassword(submit));

        FormPanel form = new FormPanel();
        form.requiredField("Current password", PanelBuilder.passwordField(currentPwd));
        form.requiredField("New password", PanelBuilder.passwordField(newPwd));
        form.requiredField("Confirm new password", PanelBuilder.passwordField(confirmPwd), "Type the new password again.");

        return PanelBuilder.detail("Change password",
                () -> credentialCards.show("list"),
                panel -> {
                    panel.add(blockNote("The password you sign in with. The vault password is changed outside the app."), "growx, wmin 0");
                    panel.add(form, "growx, wmin 0");
                    panel.add(submit, "gaptop 12");
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
        JButton submit = new JButton("Save", new IconUtil.SaveIcon(16));
        submit.setToolTipText("Save");

        rotateKey.setToolTipText("Rotate");
        rotateKey.addActionListener(_ -> onRotateAPIKey(rotateKey));

        // copy api key button
        JButton copyKey = GUIUtil.iconButton(new IconUtil.CopyIcon(16));
        copyKey.setToolTipText("Copy");
        submit.addActionListener(_ -> onEditAPIDetails(submit));
        copyKey.addActionListener(_ -> {
            if (selectedKey != null && selectedKey.getAPIKey() != null) {
                GUIUtil.copyToClipboard(selectedKey.getAPIKey(), SECRET_CLIPBOARD_MILLIS);
                copyKey.setToolTipText(COPIED_TIP);
            }
        });

        // Toggle: masking is currently on when isKeyShown is false, so flip it.
        showKey.addActionListener(_ -> setKeyMasked(isKeyShown));

        editKeySecret.setEditable(false);
        keyAppID.setEditable(true);
        keyDomainID.setEditable(true);
        keyProvider.setEditable(true);
        keyURI.setEditable(true);

        // the secret with its Copy and Show buttons on one line (the rotate button stays out, see CLAUDE.md)
        JPanel keyView = new JPanel(new MigLayout("insets 0, gapx 4", "[grow,fill][][]"));
        keyView.setOpaque(false);
        keyView.add(editKeySecret);
        keyView.add(copyKey);
        keyView.add(showKey);

        // the stacked form since 2026-10-27, with the add dialog's sections
        UITokens.primary(submit);
        FormPanel form = new FormPanel();
        form.row(PanelBuilder.sectionHeader("Key"), "growx");
        form.requiredField("Label", editKeyLabel);
        form.field("Description", editKeyDescription);
        form.requiredField("API key", keyView, "Copy it, or show it; it cannot be edited here. Delete the key and add the new one instead.");
        form.row(PanelBuilder.sectionHeader("Scope"), "growx, gaptop 10");
        form.field("App ID", keyAppID);
        form.field("Domain ID", keyDomainID, "Both, or neither.");
        form.row(PanelBuilder.sectionHeader("Provider endpoint"), "growx, gaptop 10");
        form.field("Provider", keyProvider, "Pick one, or type the name of another.");
        form.field("Base URL", keyURI);

        JButton deleteKey = new JButton("Delete", new IconUtil.DeleteIcon(16));
        deleteKey.setToolTipText("Permanently delete this API key");
        deleteKey.addActionListener(_ -> onDeleteAPIKey(selectedKey));
        JPanel actions = new JPanel(new MigLayout("insets 0, gapx 8"));
        actions.setOpaque(false);
        actions.add(submit);
        actions.add(deleteKey);

        return PanelBuilder.detail("Edit API key",
                () -> credentialCards.show("list"),
                panel -> {
                    panel.add(form, "growx, wmin 0");
                    panel.add(actions, "gaptop 12");
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

        if (external) {
            // a vendor's domain/app lives on the key's property bag (Session.APIKeyInfo)
            keyAppID.setText(Objects.requireNonNullElse(ctx.session().vendorAppOf(key), ""));
            keyDomainID.setText(Objects.requireNonNullElse(ctx.session().vendorDomainOf(key), ""));
        } else if (key.getAppID() != null) {
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
        keyProvider.setSelectedItem(provider);
        keyURI.setText(baseUrl == null ? "" : baseUrl);
        authScheme.setText(scheme == null ? "" : scheme);
        headerName.setText(header == null ? "" : header);

        credentialCards.show("editAPI");
    }

    private static String comboText(JComboBox<String> combo) {
        Object value = combo.isEditable() && combo.getEditor() != null
                ? combo.getEditor().getItem()
                : combo.getSelectedItem();
        return Objects.toString(value, "").trim();
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

        if (label.isBlank()) {
            JOptionPane.showMessageDialog(this,
                    "Label is required.",
                    "Missing information", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String appID = keyAppID.getText().trim();
        String domainID = keyDomainID.getText().trim();
        if (appID.isBlank() != domainID.isBlank()) {
            JOptionPane.showMessageDialog(this,
                    "Provide both App ID and Domain ID, or leave both empty.",
                    "Missing information", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String provider = comboText(keyProvider);
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
                    keyProvider.setSelectedItem(null);
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
                deleteConfirm(key.getName(), "API key"),
                "Delete API key", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        BackgroundTask.runCatching(this, null,
                () -> ctx.session().deleteAPIKey(key),
                () -> {
                    if (selectedKey == key) {
                        selectedKey = null;
                        editKeySecret.setText("");
                        credentialCards.show("list");
                    }
                    apiKeySection.refresh();
                    JOptionPane.showMessageDialog(this, "API key Deleted.");
                });
    }
}
