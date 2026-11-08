package io.xlogistx.nosneak.app.ui;

import io.xlogistx.nosneak.app.NSAppUtil;
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
import org.zoxweb.shared.util.GetNameDescriptionDisplay;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVPair;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.text.DefaultFormatter;
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
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

import static io.xlogistx.gui.PanelBuilder.*;

public class SubjectPanel extends JPanel {

    /** A copied API-key secret is wiped from the clipboard after this long, if it is still there. */
    static final int SECRET_CLIPBOARD_MILLIS = 60_000;
    private static final String COPIED_TIP = NSAppUtil.ApiKeysPage.COPIED.getDescription();

    // ---- Services ----
    private final CardStack cardStack = new CardStack();
    private final AppContext ctx;

    // ---- Profile fields ----
    private final JTextField firstName = new JTextField(20);
    private final JTextField lastName = new JTextField(20);
    private final JTextField dob = new JTextField(20);

    private static final String[] PROFILE_KEYS = {"firstName", "lastName", "dob"};
    private final JButton saveProfile = GUIUtil.applyProp(new JButton(new IconUtil.SaveIcon(16)), NSAppUtil.ProfilePage.SAVE);

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
    private final JButton showKey = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.VisibleIcon(16)), NSAppUtil.ApiKeysPage.SHOW_KEY);
    private final JButton rotateKey = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.RefreshIcon(16)), NSAppUtil.ApiKeysPage.ROTATE);

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
    private final CardStack profileCards = new CardStack();

    // ---- API keys page (a table page since 2026-11-04): the table, its bar and the detail pane ----
    private final ApiKeyTableModel apiKeyModel = new ApiKeyTableModel();
    private final JTable apiKeyTable = new JTable(apiKeyModel);
    private final TableRowSorter<ApiKeyTableModel> apiKeySorter = new TableRowSorter<>(apiKeyModel);
    private final JTextField apiKeySearch = new JTextField();
    private final JLabel apiKeyCount = new JLabel();
    private final JLabel apiKeyTitle = new JLabel();
    private final KeyValuePanel apiKeyFacts = new KeyValuePanel(100);
    private final CardStack credentialCards = new CardStack();

    public SubjectPanel(AppContext ctx) {
        setLayout(new BorderLayout());
        this.ctx = ctx;

        // Phase 5 of the redesign (2026-10-24): Profile and Settings sit in the shared page frame;
        // Credentials already has its own two-card layout (Phase 4). Backup and Restore are
        // blocks of the Settings page since 2026-10-26 (they had a page of their own before).
        PagePanel profilePage = new PagePanel(NSAppUtil.Screen.PROFILE.getDisplayName(), NSAppUtil.ProfilePage.PAGE.getDescription());
        profilePage.setName(NSAppUtil.ProfilePage.PAGE.getName());
        profilePage.card(scroll(buildProfileArea()));
        cardStack.add(profilePage, "Profile");
        cardStack.add(buildCredentials(), "Credentials");
        PagePanel settingsPage = new PagePanel(NSAppUtil.Screen.SETTINGS.getDisplayName(), NSAppUtil.SettingsPage.PAGE.getDescription());
        settingsPage.setName(NSAppUtil.SettingsPage.PAGE.getName());
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
            reloadApiKeys();
            populateProfile();
            if (!(boolean) e.getNewValue()) {
                cardStack.show(SECTION_PROFILE);
                apiKeySearch.setText("");
                credentialCards.show("howto");
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
            reloadApiKeys();
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

    private final JLabel syncStatus = blockStatus(NSAppUtil.SettingsPage.SYNC_STATUS);

    private JPanel buildSettingsArea() {
        JPanel area = new JPanel(new MigLayout("wrap 1, insets 0", "[grow,fill]"));
        area.add(buildAppearance());
        area.add(new JSeparator(), "gaptop 8, gapbottom 8");
        area.add(buildSync());
        area.add(new JSeparator(), "gaptop 8, gapbottom 8");
        area.add(buildAssistant());
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

        panel.add(title(NSAppUtil.SettingsPage.SYNC_TITLE));

        // WrapLabel, not a wrapping JTextArea: its height is computed at the wrap width, so the
        // block does not come out too tall on first show (the Phase 1 lesson)
        panel.add(blockNote(NSAppUtil.SettingsPage.SYNC_NOTE), "growx 0");

        JButton sync = GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/refresh.svg", 16, UITokens.text())),
                NSAppUtil.SettingsPage.SYNC);
        syncStatus.setForeground(UITokens.muted());

        sync.addActionListener(_ -> onSyncMacVendors(sync));
        panel.add(sync, "growx 0");
        panel.add(syncStatus);

        return panel;
    }

    /** The "last sync" day in the status line says it was synced; the event-driven refresh shows it. */
    private void onSyncMacVendors(JButton sync) {
        syncStatus.setText(NSAppUtil.SettingsPage.SYNC_DOWNLOADING.getDisplayName());
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
            syncStatus.setText(NSAppUtil.SettingsPage.SYNC_LOADING.getDisplayName());
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

    // ==================== Appearance (Settings block) ====================

    /** The theme combo's, its status line's, the text-size control's and the Reset button's component names, for a test. */
    static final String THEME = NSAppUtil.SettingsPage.THEME.getName();
    static final String THEME_STATUS = NSAppUtil.SettingsPage.THEME_STATUS.getName();
    static final String TEXT_SIZE = NSAppUtil.SettingsPage.TEXT_SIZE.getName();
    static final String TEXT_SIZE_RESET = NSAppUtil.SettingsPage.TEXT_SIZE_RESET.getName();

    private Consumer<NSAppUtil.Theme> onThemeChange = _ -> {};
    private BooleanSupplier themeSwitchBlocked = () -> false;

    /** Hears a theme chosen on the Appearance block, after it is stored; {@code AppShell} hands it to the frame, which rebuilds the pages. */
    public void setOnThemeChange(Consumer<NSAppUtil.Theme> listener) {
        onThemeChange = listener != null ? listener : _ -> {};
    }

    /** Says when a theme switch must wait (a scan in progress): the combo snaps back and the row says so. */
    public void setThemeSwitchBlocked(BooleanSupplier blocked) {
        themeSwitchBlocked = blocked != null ? blocked : () -> false;
    }

    /**
     * The Appearance block (2026-11-02, {@code PLAN-appearance.md}): the theme, stored per
     * installation and applied at once by rebuilding the pages, and the control text size,
     * gui-audio's {@link FontSizeWidget} over {@link UIFontSize} with its own caption and Reset
     * link ({@code withLabel().withReset()}, 2026-11-06 — the unlock screen builds the same row).
     * The size is stored by the listener {@code NoSneakMain} registers on {@code UIFontSize}, so
     * any knob is remembered.
     */
    private JPanel buildAppearance() {
        return appearanceBlock(AppPrefs.theme(), theme -> {
            AppPrefs.theme(theme);
            onThemeChange.accept(theme);
        }, () -> themeSwitchBlocked.getAsBoolean());
    }

    /**
     * The block itself, in the Assistant block's shape; a factory so a test can build and paint it
     * on its own. {@code onTheme} hears a theme other than the one in force unless {@code blocked}
     * says so, in which case the combo snaps back and the status line reads the busy note.
     */
    static JPanel appearanceBlock(NSAppUtil.Theme current, Consumer<NSAppUtil.Theme> onTheme, BooleanSupplier blocked) {
        JPanel panel = new JPanel(new MigLayout("wrap 1, insets 12, gapy 6", "[grow,fill]"));

        panel.add(title(NSAppUtil.SettingsPage.APPEARANCE_TITLE));
        panel.add(blockNote(NSAppUtil.SettingsPage.APPEARANCE_NOTE), "growx 0");

        JComboBox<NSAppUtil.Theme> themes = GUIUtil.applyProp(new JComboBox<>(NSAppUtil.Theme.values()), NSAppUtil.SettingsPage.THEME);
        themes.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                super.getListCellRendererComponent(list, value, index, selected, focus);
                if (value instanceof NSAppUtil.Theme t) {
                    setText(t.getDisplayName());
                    setToolTipText(t.getDescription());
                }
                return this;
            }
        });
        NSAppUtil.Theme[] inForce = {current != null ? current : NSAppUtil.Theme.LIGHT};
        themes.setSelectedItem(inForce[0]);
        JLabel status = blockStatus(NSAppUtil.SettingsPage.THEME_STATUS);
        status.setText(NSAppUtil.SettingsPage.THEME_NOTE.getDisplayName());
        boolean[] reverting = {false};
        themes.addActionListener(_ -> {
            if (reverting[0]) return;
            NSAppUtil.Theme chosen = (NSAppUtil.Theme) themes.getSelectedItem();
            if (chosen == null || chosen == inForce[0]) return;
            if (blocked.getAsBoolean()) {
                reverting[0] = true;
                themes.setSelectedItem(inForce[0]);
                reverting[0] = false;
                status.setText(NSAppUtil.SettingsPage.THEME_BUSY.getDisplayName());
                status.setForeground(UITokens.danger());
                return;
            }
            inForce[0] = chosen;
            status.setText(NSAppUtil.SettingsPage.THEME_NOTE.getDisplayName());
            status.setForeground(UITokens.muted());
            onTheme.accept(chosen);
        });
        JLabel themeLabel = GUIUtil.applyProp(new JLabel(), NSAppUtil.SettingsPage.THEME_LABEL);
        themeLabel.setLabelFor(themes);
        JPanel themeRow = new JPanel(new MigLayout("insets 0, gapx 8", "[][][]"));
        themeRow.setOpaque(false);
        themeRow.add(themeLabel);
        themeRow.add(themes);
        themeRow.add(status);
        panel.add(themeRow, "growx 0");

        FontSizeWidget size = GUIUtil.applyProp(new FontSizeWidget().withLabel().withReset(), NSAppUtil.SettingsPage.TEXT_SIZE);
        GUIUtil.applyProp(size.getLabel(), NSAppUtil.SettingsPage.TEXT_SIZE_LABEL);
        GUIUtil.applyProp(size.getResetButton(), NSAppUtil.SettingsPage.TEXT_SIZE_RESET);
        panel.add(size, "growx 0");

        return panel;
    }

    // ==================== Assistant (Settings block) ====================

    /** The reply timeout spinner's component name ({@link NSAppUtil.SettingsPage#REPLY_TIMEOUT}). */
    static final String REPLY_TIMEOUT = NSAppUtil.SettingsPage.REPLY_TIMEOUT.getName();

    private IntConsumer onAssistantTimeoutChange = _ -> {};

    /**
     * Hears every change of the Assistant block's reply timeout, in seconds, after it is stored;
     * {@code AppShell} hands it to the assistant's context so the next request uses it.
     */
    public void setOnAssistantTimeoutChange(IntConsumer listener) {
        onAssistantTimeoutChange = listener != null ? listener : _ -> {};
    }

    /**
     * The Assistant block (2026-10-31, the maintainer: "the ai apis call sometimes they timeout
     * can we set the timeout as parameter in setting"): one spinner, the seconds a provider may
     * take to answer a request. The default is the usual 40 s; the setting is there to stretch it
     * when an endpoint is congested. Stored per installation in {@link AppPrefs} and pushed to
     * the assistant through {@link #setOnAssistantTimeoutChange} the moment it changes.
     */
    private JPanel buildAssistant() {
        return assistantBlock(AppPrefs.aiTimeoutSeconds(), seconds -> {
            AppPrefs.aiTimeoutSeconds(seconds);
            onAssistantTimeoutChange.accept(seconds);
        });
    }

    /** The block itself, in the Sync block's shape; a factory so a test can build and paint it on its own. */
    static JPanel assistantBlock(int seconds, IntConsumer onChange) {
        JPanel panel = new JPanel(new MigLayout("wrap 1, insets 12, gapy 6", "[grow,fill]"));

        panel.add(title(NSAppUtil.SettingsPage.ASSISTANT_TITLE));
        panel.add(blockNote(NSAppUtil.SettingsPage.ASSISTANT_NOTE), "growx 0");

        JSpinner spinner = new JSpinner(new SpinnerNumberModel(AppPrefs.clampAiTimeout(seconds),
                AppPrefs.AI_TIMEOUT_MIN, AppPrefs.AI_TIMEOUT_MAX, 10));
        GUIUtil.applyProp(spinner, NSAppUtil.SettingsPage.REPLY_TIMEOUT);
        JFormattedTextField field = ((JSpinner.DefaultEditor) spinner.getEditor()).getTextField();
        field.setColumns(4);
        // a typed value counts as soon as it is valid, not only on Enter or focus loss
        if (field.getFormatter() instanceof DefaultFormatter df) df.setCommitsOnValidEdit(true);
        spinner.addChangeListener(_ -> onChange.accept(((Number) spinner.getValue()).intValue()));

        JLabel label = GUIUtil.applyProp(new JLabel(), NSAppUtil.SettingsPage.REPLY_TIMEOUT_LABEL);
        label.setLabelFor(spinner);
        JPanel row = new JPanel(new MigLayout("insets 0, gapx 8", "[][][]"));
        row.setOpaque(false);
        row.add(label);
        row.add(spinner);
        row.add(GUIUtil.applyProp(new JLabel(), NSAppUtil.SettingsPage.REPLY_TIMEOUT_UNIT));
        panel.add(row, "growx 0");

        return panel;
    }

    // ==================== Backup and Restore (Settings blocks) ====================

    private static final String[] RESTORE_MODES = {
            NSAppUtil.SettingsPage.RESTORE_MODE_MERGE.getDisplayName(), NSAppUtil.SettingsPage.RESTORE_MODE_REPLACE.getDisplayName()};

    /** A block's note: a WrapLabel at the Sync block's width (its height is right on first show), named and worded by its descriptor. */
    private static WrapLabel blockNote(GetNameDescriptionDisplay ref) {
        WrapLabel note = GUIUtil.applyProp(new WrapLabel(ref.getDisplayName()), ref);
        note.setWrapWidth(480);
        note.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        return note;
    }

    /** A block's title, named by its descriptor. */
    private static JLabel title(GetNameDescriptionDisplay ref) {
        return GUIUtil.applyProp(PanelBuilder.title(ref.getDisplayName()), ref);
    }

    /** A block's muted status line, named by its descriptor; its text is filled at run time. */
    private static JLabel blockStatus(GetNameDescriptionDisplay ref) {
        JLabel status = GUIUtil.applyProp(new JLabel(" "), ref);
        status.setForeground(UITokens.muted());
        return status;
    }

    /**
     * The Restore block (2026-10-26; note and status in the Sync block's shape since 2026-10-27):
     * loads a backup archive into the store in Merge or Replace mode and signs the subject out.
     */
    private JPanel buildDBRestore() {
        JPanel panel = new JPanel(new MigLayout("wrap 1, insets 12, gapy 6", "[grow,fill]"));

        panel.add(title(NSAppUtil.SettingsPage.RESTORE_TITLE));
        panel.add(blockNote(NSAppUtil.SettingsPage.RESTORE_NOTE), "growx 0");

        JComboBox<String> mode = GUIUtil.applyProp(new JComboBox<>(RESTORE_MODES), NSAppUtil.SettingsPage.RESTORE_MODE);
        JButton restore = GUIUtil.applyProp(new JButton(new IconUtil.RollbackIcon(16)), NSAppUtil.SettingsPage.RESTORE);
        JLabel status = blockStatus(NSAppUtil.SettingsPage.RESTORE_STATUS);

        restore.addActionListener(_ -> onRestoreBackup(restore, status, mode.getSelectedIndex()));
        panel.add(mode, "growx 0, width 240!");
        panel.add(restore, "growx 0");
        panel.add(status);

        return panel;
    }

    private void onRestoreBackup(JButton restore, JLabel status, int modeIndex) {
        if (!(ctx.session().getDomainSecurityManager().getDataStore() instanceof H2PDataStore ds)) {
            JOptionPane.showMessageDialog(this, "This data store cannot be restored.",
                    NSAppUtil.SettingsPage.RESTORE_ERROR_DIALOG.getDisplayName(), JOptionPane.ERROR_MESSAGE);
            return;
        }

        H2PDataStore.RestoreMode mode = modeIndex == 1
                ? H2PDataStore.RestoreMode.WIPE_AND_LOAD
                : H2PDataStore.RestoreMode.MERGE;

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(NSAppUtil.SettingsPage.RESTORE_DIALOG.getDisplayName());
        chooser.setCurrentDirectory(AppPrefs.fileDirectory());
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File source = chooser.getSelectedFile();
        AppPrefs.fileDirectory(source);
        String warning = mode == H2PDataStore.RestoreMode.WIPE_AND_LOAD
                ? "Every record in this store will be deleted and replaced with the contents of\n"
                + source.getName() + ".\n\nThis cannot be undone. Continue?"
                : "Records from " + source.getName() + " will be added to this store, overwriting\n"
                + "any that share the same id.\n\nContinue?";

        if (JOptionPane.showConfirmDialog(this, warning, NSAppUtil.SettingsPage.RESTORE_DIALOG.getDisplayName(),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.OK_OPTION) {
            return;
        }

        status.setText(NSAppUtil.SettingsPage.RESTORING.getDisplayName());
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
                    status.setText(NSAppUtil.SettingsPage.RESTORED.getDisplayName() + " " + source.getName());
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

        panel.add(title(NSAppUtil.SettingsPage.BACKUP_TITLE));
        panel.add(blockNote(NSAppUtil.SettingsPage.BACKUP_NOTE), "growx 0");

        JButton export = GUIUtil.applyProp(new JButton(new IconUtil.SaveIcon(16)), NSAppUtil.SettingsPage.EXPORT);
        JLabel status = blockStatus(NSAppUtil.SettingsPage.BACKUP_STATUS);

        export.addActionListener(_ -> onExportBackup(export, status));
        panel.add(export, "growx 0");
        panel.add(status);

        return panel;
    }

    private void onExportBackup(JButton export, JLabel status) {
        if (!(ctx.session().getDomainSecurityManager().getDataStore() instanceof H2PDataStore ds)) {
            JOptionPane.showMessageDialog(this, "This data store cannot be exported.",
                    NSAppUtil.SettingsPage.BACKUP_ERROR_DIALOG.getDisplayName(), JOptionPane.ERROR_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(NSAppUtil.SettingsPage.EXPORT_DIALOG.getDisplayName());
        chooser.setCurrentDirectory(AppPrefs.fileDirectory());
        chooser.setSelectedFile(new File(NoSneakMain.dbName + "-backup-" + LocalDate.now() + ".zip"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File target = chooser.getSelectedFile();
        AppPrefs.fileDirectory(target);
        if (target.exists() && JOptionPane.showConfirmDialog(this,
                target.getName() + " already exists. Replace it?", NSAppUtil.SettingsPage.EXPORT_DIALOG.getDisplayName(),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.OK_OPTION) {
            return;
        }

        status.setText(NSAppUtil.SettingsPage.EXPORTING.getDisplayName());
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
                    status.setText(NSAppUtil.SettingsPage.EXPORTED.getDisplayName() + " " + target.getName() + " — " + (size / 1024) + " KB");
                    JOptionPane.showMessageDialog(this, "Backup written to\n" + target.getAbsolutePath());
                });
    }

    // ============================ Profile & identifiers ============================

    /** The Profile page's content: the profile card or the address detail, both 480 px wide like the Settings blocks. */
    private JPanel buildProfileArea() {
        profileCards.add(buildProfile(), "profile");
        profileCards.add(buildEditAddress(), "editAddress");
        profileCards.add(buildChangePassword(), "changePassword");
        profileCards.show("profile");

        JPanel anchor = new JPanel(new MigLayout("insets 0", "[480!]"));
        anchor.setOpaque(false);
        anchor.add(profileCards.view(), "growx, aligny top");
        JPanel p = new JPanel(new BorderLayout());
        p.setOpaque(false);
        p.add(anchor, BorderLayout.NORTH);
        return p;
    }

    private final JLabel profileStatus = blockStatus(NSAppUtil.ProfilePage.STATUS);

    /**
     * The profile card (re-laid out 2026-10-27 in the Settings page's shape): four blocks
     * separated by rules — <b>Name</b> (a {@link FormPanel} with the page's one primary action,
     * Save changes, and a status line instead of a dialog), <b>Password</b> (moved here from the
     * API Keys page on 2026-11-04: the one row's Edit flips to the change-password card),
     * <b>Identifiers</b> and <b>Addresses</b> (the three {@link ListSection}s, each with a
     * description of what the list is for).
     */
    private JPanel buildProfile() {
        passwordSection = ListSection.of(() -> ctx.session().getAllCredentialForUserByType(CredentialInfo.Type.PASSWORD).stream().filter(CIPassword.class::isInstance).map(CIPassword.class::cast).toList())
                .title(NSAppUtil.ProfilePage.PASSWORD.getDisplayName())
                .description(NSAppUtil.ProfilePage.PASSWORD.getDescription())
                .label(SubjectPanel::passwordLabel)
                .onEdit(_ -> () -> profileCards.show("changePassword"))
                .build();

        identifiers = ListSection.of(() -> ctx.session().getAllPrincipalIDForLoggedInUser())
                .title(NSAppUtil.ProfilePage.IDENTIFIERS.getDisplayName())
                .description(NSAppUtil.ProfilePage.IDENTIFIERS.getDescription())
                .addButton(NSAppUtil.ProfilePage.IDENTIFIERS_ADD.getDisplayName(), this::onAddIdentifier)
                .label(PrincipalIdentifier::getPrincipalID)
                .onRemove(p -> () -> onRemoveIdentifier(p))
                .build();

        addressSection = ListSection.of(() -> ctx.session().getAllAddresses())
                .title(NSAppUtil.ProfilePage.ADDRESSES.getDisplayName())
                .description(NSAppUtil.ProfilePage.ADDRESSES.getDescription())
                .addButton(NSAppUtil.ProfilePage.ADDRESSES_ADD.getDisplayName(), this::onAddAddress)
                .label(this::addressLabel)
                .onEdit(p -> () -> onEditAddress(p))
                .onRemove(p -> () -> onRemoveAddress(p))
                .emptyText(NSAppUtil.ProfilePage.ADDRESSES_EMPTY.getDisplayName())
                .build();

        FormPanel form = new FormPanel();
        form.field(NSAppUtil.ProfilePage.FIRST_NAME.getDisplayName(), GUIUtil.applyProp(firstName, NSAppUtil.ProfilePage.FIRST_NAME_FIELD));
        form.field(NSAppUtil.ProfilePage.LAST_NAME.getDisplayName(), GUIUtil.applyProp(lastName, NSAppUtil.ProfilePage.LAST_NAME_FIELD));
        form.field(NSAppUtil.ProfilePage.DOB.getDisplayName(), GUIUtil.applyProp(dob, NSAppUtil.ProfilePage.DOB_FIELD), NSAppUtil.ProfilePage.DOB.getDescription());
        UITokens.primary(saveProfile);
        saveProfile.addActionListener(_ -> onSaveProfile());

        JPanel name = new JPanel(new MigLayout("wrap 1, insets 12, gapy 6", "[grow,fill]"));
        name.setOpaque(false);
        name.add(title(NSAppUtil.ProfilePage.NAME_TITLE));
        name.add(blockNote(NSAppUtil.ProfilePage.NAME_NOTE), "growx 0");
        name.add(form, "growx");
        name.add(saveProfile, "growx 0, gaptop 10");
        name.add(profileStatus);

        JPanel card = new JPanel(new MigLayout("wrap 1, insets 0", "[grow,fill]"));
        card.setOpaque(false);
        card.add(name);
        card.add(new JSeparator(), "gaptop 8, gapbottom 8");
        card.add(passwordSection, "gapx 12 12");
        card.add(new JSeparator(), "gaptop 16, gapbottom 8");
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
        profileStatus.setText(NSAppUtil.ProfilePage.SAVING.getDisplayName());
        BackgroundTask.runCatching(this, saveProfile,
                () -> ctx.session().saveProfile(fields),
                () -> profileStatus.setText(NSAppUtil.ProfilePage.SAVED.getDisplayName()));
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
        addRow(form, NSAppUtil.ProfilePage.ADD_IDENTIFIER_KIND.getDisplayName(), GUIUtil.applyProp(kind, NSAppUtil.ProfilePage.ADD_IDENTIFIER_KIND));
        addRow(form, NSAppUtil.ProfilePage.ADD_IDENTIFIER_VALUE.getDisplayName(), GUIUtil.applyProp(value, NSAppUtil.ProfilePage.ADD_IDENTIFIER_VALUE_FIELD));

        int ok = JOptionPane.showConfirmDialog(this, form, NSAppUtil.ProfilePage.ADD_IDENTIFIER_DIALOG.getDisplayName(),
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        String id = value.getText().trim();
        if (id.isEmpty()) return;
        if ("Email".equals(kind.getSelectedItem()) && !FilterType.EMAIL.isValid(id)) {
            JOptionPane.showMessageDialog(this, "Enter a valid email address.",
                    NSAppUtil.ProfilePage.INVALID_EMAIL_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
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
                deleteConfirm(p.getPrincipalID(), "identifier"), NSAppUtil.ProfilePage.DELETE_IDENTIFIER_DIALOG.getDisplayName(),
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
                NSAppUtil.ProfilePage.DELETE_ADDRESS_DIALOG.getDisplayName(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
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
        JButton save = UITokens.primary(GUIUtil.applyProp(new JButton(new IconUtil.SaveIcon(16)), NSAppUtil.AddressEditor.SAVE));
        save.addActionListener(_ -> onSaveAddress(save));

        // the same stacked form as the Name block (2026-10-27); Back returns to the profile card
        FormPanel form = new FormPanel();
        form.field(NSAppUtil.AddressEditor.LABEL.getDisplayName(), GUIUtil.applyProp(addrLabel, NSAppUtil.AddressEditor.LABEL_FIELD), NSAppUtil.AddressEditor.LABEL.getDescription());
        form.field(NSAppUtil.AddressEditor.STREET.getDisplayName(), GUIUtil.applyProp(addrStreet, NSAppUtil.AddressEditor.STREET_FIELD));
        form.field(NSAppUtil.AddressEditor.CITY.getDisplayName(), GUIUtil.applyProp(addrCity, NSAppUtil.AddressEditor.CITY_FIELD));
        form.field(NSAppUtil.AddressEditor.REGION.getDisplayName(), GUIUtil.applyProp(addrRegion, NSAppUtil.AddressEditor.REGION_FIELD));
        form.field(NSAppUtil.AddressEditor.POSTAL.getDisplayName(), GUIUtil.applyProp(addrPostCode, NSAppUtil.AddressEditor.POSTAL_FIELD));
        form.field(NSAppUtil.AddressEditor.COUNTRY.getDisplayName(), GUIUtil.applyProp(addrCountry, NSAppUtil.AddressEditor.COUNTRY_FIELD));

        JPanel detail = PanelBuilder.detail(NSAppUtil.AddressEditor.EDITOR.getDisplayName(),
                () -> profileCards.show("profile"),
                panel -> {
                    panel.add(blockNote(NSAppUtil.AddressEditor.NOTE), "growx, wmin 0");
                    panel.add(form, "growx, wmin 0");
                    panel.add(save, "gaptop 12");
                });
        detail.setName(NSAppUtil.AddressEditor.EDITOR.getName());
        return detail;
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
                    NSAppUtil.AddressEditor.MISSING_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
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

    // ============================ API keys (table page) ============================

    /**
     * The API keys page, in the shape of the Probe groups and Scan history pages since 2026-11-04
     * (the maintainer: "the api key panel it is still like the old look, make it standard like the
     * rest of the application"): the page frame with the one primary action, <b>Add API key</b>;
     * a bar with a search box and the count; a split card — the keys table on the left
     * ({@link ApiKeyTableModel}, columns from {@link NSAppUtil.ApiKeyColumn}), the detail stack
     * {@code credentialCards} on the right: <b>howto</b> with nothing selected, <b>key</b> for the
     * selected row (its label with Edit / Delete, its facts), <b>editAPI</b> the editor.
     */
    private JPanel buildCredentials() {
        PagePanel page = new PagePanel(NSAppUtil.Screen.API_KEYS.getDisplayName(), NSAppUtil.ApiKeysPage.PAGE.getDescription());
        page.setName(NSAppUtil.ApiKeysPage.PAGE.getName());
        JButton addKey = UITokens.primary(GUIUtil.applyProp(new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)), NSAppUtil.ApiKeysPage.ADD));
        addKey.addActionListener(_ -> onAddAPIKey());
        page.action(addKey);

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][]push"));
        bar.setOpaque(false);
        GUIUtil.applyProp(apiKeySearch, NSAppUtil.ApiKeysPage.SEARCH);
        apiKeySearch.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        bar.add(apiKeySearch, "growx");
        GUIUtil.applyProp(apiKeyCount, NSAppUtil.ApiKeysPage.COUNT);
        apiKeyCount.setForeground(UITokens.muted());
        apiKeyCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(apiKeyCount);
        page.add(bar, "growx");

        Tables.style(GUIUtil.applyProp(apiKeyTable, NSAppUtil.ApiKeysPage.TABLE));
        Tables.width(apiKeyTable, ApiKeyTableModel.COL_LABEL, 160);
        Tables.width(apiKeyTable, ApiKeyTableModel.COL_PROVIDER, 130);
        Tables.width(apiKeyTable, ApiKeyTableModel.COL_BASE_URL, 220);
        Tables.width(apiKeyTable, ApiKeyTableModel.COL_SCOPE, 140);
        Tables.width(apiKeyTable, ApiKeyTableModel.COL_DESCRIPTION, 200);
        apiKeyTable.getColumnModel().getColumn(ApiKeyTableModel.COL_BASE_URL).setCellRenderer(new MonoRenderer());
        apiKeyTable.setRowSorter(apiKeySorter);
        apiKeyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        apiKeyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showKeyDetail(selectedKeyRow());
        });
        apiKeyTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() != 2) return;
                KeyRow row = selectedKeyRow();
                if (row != null) onEditAPIKey(row.key());
            }
        });
        apiKeySearch.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                filterApiKeys();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                filterApiKeys();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                filterApiKeys();
            }
        });

        JScrollPane tableScroll = new JScrollPane(apiKeyTable);
        tableScroll.setBorder(BorderFactory.createEmptyBorder());
        tableScroll.getViewport().setBackground(UITokens.surface());
        tableScroll.setMinimumSize(new Dimension(0, 0));

        credentialCards.add(buildKeyHowTo(), "howto");
        credentialCards.add(buildKeyCard(), "key");
        credentialCards.add(scroll(buildEditAPIKey()), "editAPI");
        JComponent detail = credentialCards.view();
        detail.setBackground(UITokens.surfaceAlt());
        detail.setOpaque(true);
        detail.setBorder(BorderFactory.createMatteBorder(0, 1, 0, 0, UITokens.border()));
        detail.setMinimumSize(new Dimension(0, 0));
        credentialCards.show("howto");

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScroll, detail);
        split.setResizeWeight(0.55);
        split.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        split.setDividerSize(6);
        split.setMinimumSize(new Dimension(0, 0));
        page.add(split, "grow, push");
        return page;
    }

    /** The detail pane with nothing selected: what a key is for, and the two steps to use one. */
    private JPanel buildKeyHowTo() {
        JPanel p = new JPanel(new MigLayout("insets 20, wrap 1, gapy 6", "[grow,fill]"));
        p.setOpaque(false);
        JLabel t = GUIUtil.applyProp(new JLabel(), NSAppUtil.ApiKeysPage.HOWTO_TITLE);
        t.setFont(UITokens.font(Font.BOLD, 2f));
        p.add(t, "gapbottom 4");
        WrapLabel what = GUIUtil.applyProp(new WrapLabel(""), NSAppUtil.ApiKeysPage.HOWTO_TEXT);
        what.setWrapWidth(300);
        what.setForeground(UITokens.muted());
        p.add(what, "gapbottom 8");

        JButton add = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ApiKeysPage.HOWTO_ADD));
        add.addActionListener(_ -> onAddAPIKey());
        p.add(add, "growx 0");
        p.add(howToNote(NSAppUtil.ApiKeysPage.HOWTO_ADD.getDescription()));

        JButton providers = UITokens.link(GUIUtil.applyProp(new JButton(), NSAppUtil.ApiKeysPage.HOWTO_PROVIDERS));
        providers.addActionListener(_ -> ctx.nav().show(NSAppUtil.Screen.PROVIDERS));
        p.add(providers, "growx 0, gaptop 8");
        p.add(howToNote(NSAppUtil.ApiKeysPage.HOWTO_PROVIDERS.getDescription()));
        return p;
    }

    private static WrapLabel howToNote(String text) {
        WrapLabel l = new WrapLabel(text);
        l.setWrapWidth(290);
        l.setForeground(UITokens.muted());
        l.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));
        return l;
    }

    /** The detail pane for a selected key: the label with Edit / Delete, then its facts (never the secret). */
    private JPanel buildKeyCard() {
        JPanel p = new JPanel(new MigLayout("insets 16, wrap 1, gapy 8, fill", "[grow,fill]", "[][]push"));
        p.setOpaque(false);
        GUIUtil.applyProp(apiKeyTitle, NSAppUtil.ApiKeysPage.KEY_TITLE);
        apiKeyTitle.setFont(UITokens.font(Font.BOLD, 2f));
        JPanel header = new JPanel(new MigLayout("insets 0, gapx 8", "[grow][][]"));
        header.setOpaque(false);
        header.add(apiKeyTitle, "growx, wmin 0");
        JButton edit = GUIUtil.applyProp(new JButton(new IconUtil.EditIcon(16)), NSAppUtil.ApiKeysPage.EDIT);
        edit.addActionListener(_ -> {
            KeyRow row = selectedKeyRow();
            if (row != null) onEditAPIKey(row.key());
        });
        JButton delete = GUIUtil.applyProp(new JButton(new IconUtil.DeleteIcon(16)), NSAppUtil.ApiKeysPage.DELETE);
        delete.setForeground(UITokens.danger());
        delete.addActionListener(_ -> {
            KeyRow row = selectedKeyRow();
            if (row != null) onDeleteAPIKey(row.key());
        });
        for (JButton b : new JButton[]{edit, delete}) {
            b.putClientProperty("JButton.buttonType", "toolBarButton");
            header.add(b);
        }
        p.add(header);
        p.add(apiKeyFacts);
        return p;
    }

    /** Fills the detail pane for {@code row}; null shows the how-to card. The editor, when open, stays open. */
    private void showKeyDetail(KeyRow row) {
        if (row == null) {
            credentialCards.show("howto");
            return;
        }
        apiKeyTitle.setText(row.label());
        apiKeyFacts.clear();
        WrapLabel description = apiKeyFacts.put(NSAppUtil.ApiKeysPage.FACT_DESCRIPTION.getDisplayName(), row.description().isEmpty() ? "—" : row.description());
        if (description != null) description.setWrapWidth(260);
        apiKeyFacts.put(NSAppUtil.ApiKeysPage.FACT_PROVIDER.getDisplayName(), row.provider().isEmpty() ? "—" : row.provider());
        apiKeyFacts.putMono(NSAppUtil.ApiKeysPage.FACT_BASE_URL.getDisplayName(), row.baseUrl().isEmpty() ? "—" : row.baseUrl());
        apiKeyFacts.putMono(NSAppUtil.ApiKeysPage.FACT_SCOPE.getDisplayName(), row.scope().isEmpty() ? "—" : row.scope());
        if (!row.auth().isEmpty()) apiKeyFacts.putMono(NSAppUtil.ApiKeysPage.FACT_AUTH.getDisplayName(), row.auth());
        apiKeyFacts.put(NSAppUtil.ApiKeysPage.FACT_KIND.getDisplayName(), row.kind());
        apiKeyFacts.put(NSAppUtil.ApiKeysPage.FACT_SECRET.getDisplayName(), NSAppUtil.ApiKeysPage.FACT_SECRET.getDescription());
        apiKeyFacts.revalidate();
        apiKeyFacts.repaint();
        credentialCards.show("key");
    }

    private KeyRow selectedKeyRow() {
        int row = apiKeyTable.getSelectedRow();
        return row < 0 ? null : apiKeyModel.at(apiKeyTable.convertRowIndexToModel(row));
    }

    /**
     * Re-reads the subject's keys off the EDT (the session's metadata readers walk each key's
     * property bag) and rebuilds the table; the selection survives by GUID. Signed out, the
     * session returns nothing and the table empties.
     */
    private void reloadApiKeys() {
        KeyRow before = selectedKeyRow();
        BackgroundTask.run(this, null,
                () -> {
                    List<KeyRow> rows = new ArrayList<>();
                    for (CredentialInfo c : ctx.session().getAllCredentialForUserByType(CredentialInfo.Type.API_KEY)) {
                        if (c instanceof SubjectAPIKey k) rows.add(keyRow(k));
                    }
                    rows.sort(Comparator.comparing(KeyRow::label, String.CASE_INSENSITIVE_ORDER));
                    return rows;
                },
                rows -> {
                    apiKeyModel.setRows(rows);
                    filterApiKeys();
                    if (before != null && selectKeyByGUID(before.key().getGUID())) return;
                    apiKeyTable.clearSelection();
                    showKeyDetail(null);
                });
    }

    /** One table row: the key and the strings the page shows for it, read once here. */
    private KeyRow keyRow(SubjectAPIKey k) {
        Session session = ctx.session();
        boolean external = session.isExternalKey(k);
        String label = k.getName();
        if (label == null || label.isBlank()) label = "API key";
        String scope;
        if (external) {
            String d = session.vendorDomainOf(k), a = session.vendorAppOf(k);
            scope = d == null || a == null ? "" : d + " · " + a;
        } else {
            scope = k.getAppID() == null ? "" : k.getAppID().getDomainID() + " · " + k.getAppID().getAppID();
        }
        String auth = Objects.toString(session.authTypeOf(k), "").trim();
        String header = Objects.toString(session.headerNameOf(k), "").trim();
        if (!header.isEmpty()) auth = auth.isEmpty() ? header : auth + " · " + header;
        return new KeyRow(k, label,
                Objects.toString(k.getDescription(), "").trim(),
                Objects.toString(session.providerOf(k), "").trim(),
                Objects.toString(session.baseUrlOf(k), "").trim(),
                scope, auth,
                (external ? NSAppUtil.ApiKeysPage.KIND_EXTERNAL : NSAppUtil.ApiKeysPage.KIND_INTERNAL).getDisplayName());
    }

    private boolean selectKeyByGUID(String guid) {
        if (guid == null) return false;
        for (int i = 0; i < apiKeyTable.getRowCount(); i++) {
            if (guid.equals(apiKeyModel.at(apiKeyTable.convertRowIndexToModel(i)).key().getGUID())) {
                apiKeyTable.setRowSelectionInterval(i, i);
                apiKeyTable.scrollRectToVisible(apiKeyTable.getCellRect(i, 0, true));
                return true;
            }
        }
        return false;
    }

    private void filterApiKeys() {
        String q = apiKeySearch.getText().trim().toLowerCase(Locale.ROOT);
        apiKeySorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ApiKeyTableModel, ? extends Integer> entry) {
                return entry.getModel().at(entry.getIdentifier()).matches(q);
            }
        });
        int shown = apiKeyTable.getRowCount(), all = apiKeyModel.getRowCount();
        apiKeyCount.setText(all == 0 ? NSAppUtil.ApiKeysPage.KEYS_EMPTY.getDisplayName()
                : shown == all ? all + (all == 1 ? " key" : " keys") : shown + " of " + all + " keys");
    }

    /** A key as the table shows it; {@code matches} is the search box's rule. */
    record KeyRow(SubjectAPIKey key, String label, String description, String provider, String baseUrl,
                  String scope, String auth, String kind) {
        boolean matches(String q) {
            if (q.isEmpty()) return true;
            for (String s : new String[]{label, description, provider, baseUrl, scope}) {
                if (s.toLowerCase(Locale.ROOT).contains(q)) return true;
            }
            return false;
        }
    }

    /** The keys table: columns from {@link NSAppUtil.ApiKeyColumn}, rows of {@link KeyRow}. */
    static final class ApiKeyTableModel extends AbstractTableModel {
        static final int COL_LABEL = NSAppUtil.ApiKeyColumn.LABEL.ordinal(),
                COL_PROVIDER = NSAppUtil.ApiKeyColumn.PROVIDER.ordinal(),
                COL_BASE_URL = NSAppUtil.ApiKeyColumn.BASE_URL.ordinal(),
                COL_SCOPE = NSAppUtil.ApiKeyColumn.SCOPE.ordinal(),
                COL_DESCRIPTION = NSAppUtil.ApiKeyColumn.DESCRIPTION.ordinal();
        private final List<KeyRow> rows = new ArrayList<>();

        void setRows(List<KeyRow> fresh) {
            rows.clear();
            rows.addAll(fresh);
            fireTableDataChanged();
        }

        KeyRow at(int modelRow) {
            return rows.get(modelRow);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return NSAppUtil.ApiKeyColumn.values().length;
        }

        @Override
        public String getColumnName(int column) {
            return NSAppUtil.ApiKeyColumn.values()[column].getDisplayName();
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return false;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            KeyRow r = rows.get(rowIndex);
            return switch (NSAppUtil.ApiKeyColumn.values()[columnIndex]) {
                case LABEL -> r.label();
                case PROVIDER -> r.provider().isEmpty() ? "—" : r.provider();
                case BASE_URL -> r.baseUrl();
                case SCOPE -> r.scope().isEmpty() ? "—" : r.scope();
                case DESCRIPTION -> r.description();
            };
        }
    }

    private static final class MonoRenderer extends javax.swing.table.DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setFont(UITokens.mono(-1.5f));
            if (!isSelected) setForeground(UITokens.muted());
            return this;
        }
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
            JOptionPane.showMessageDialog(this, e.getMessage(), NSAppUtil.ApiKeysPage.ERROR_DIALOG.getDisplayName(), JOptionPane.ERROR_MESSAGE);
            return;
        }

        // --- Generate card: label + read-only (copyable) key + Copy ---
        JTextField genLabel = GUIUtil.applyProp(textField(""), NSAppUtil.ApiKeysPage.GENERATE_LABEL_FIELD);
        JTextField genDescription = GUIUtil.applyProp(textField(""), NSAppUtil.ApiKeysPage.DESCRIPTION_FIELD);
        JTextField genKey = GUIUtil.applyProp(new JTextField(generated.getAPIKey(), 28), NSAppUtil.ApiKeysPage.GENERATE_KEY);
        genKey.setEditable(false);               // selectable + copyable, not editable
        JButton copy = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.CopyIcon(16)), NSAppUtil.ApiKeysPage.GENERATE_COPY);
        copy.addActionListener(_ -> {
            GUIUtil.copyToClipboard(genKey.getText(), SECRET_CLIPBOARD_MILLIS);
            copy.setIcon(new IconUtil.CheckIcon(16));
            copy.setToolTipText(COPIED_TIP);
        });
        JButton refresh = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.RefreshIcon(16)), NSAppUtil.ApiKeysPage.GENERATE_REFRESH);
        refresh.addActionListener(_ -> {
            APIKey<String> refreshed;
            try {
                refreshed = ctx.session().generateAPIKey();
            } catch (AccessSecurityException e) {
                JOptionPane.showMessageDialog(this, e.getMessage(), NSAppUtil.ApiKeysPage.ERROR_DIALOG.getDisplayName(), JOptionPane.ERROR_MESSAGE);
                return;
            }
            genKey.setText(refreshed.getAPIKey());
            // new key → the old "Copied" state no longer applies
            copy.setIcon(new IconUtil.CopyIcon(16));
            copy.setToolTipText(NSAppUtil.ApiKeysPage.GENERATE_COPY.getDescription());
        });
        JPanel copyRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        copyRow.add(genKey);
        copyRow.add(refresh);
        copyRow.add(copy);

        JPanel generateCard = new JPanel(new MigLayout(
                "wrap 2, insets 12, gapx 10, gapy 6",
                "[left][grow,fill]"
        ));

        addSection(generateCard, NSAppUtil.ApiKeysPage.SECTION_KEY.getDisplayName());
        addRow(generateCard, NSAppUtil.ApiKeysPage.LABEL.getDisplayName(), genLabel);
        addRow(generateCard, NSAppUtil.ApiKeysPage.DESCRIPTION.getDisplayName(), genDescription);
        addRow(generateCard, NSAppUtil.ApiKeysPage.GENERATE_KEY.getDisplayName(), copyRow);

        // --- Enter-existing card: the stacked form (2026-10-27), see newAddKeyForm ---
        AddKeyForm in = newAddKeyForm();

        // --- cards (the generate card stays registered for when local keys return) ---
        CardStack cards = new CardStack();
        cards.add(generateCard, "generate");
        cards.add(in.panel, "input");
        cards.show("input");

        String[] actions = {NSAppUtil.ApiKeysPage.ADD_CREATE.getDisplayName(), NSAppUtil.ApiKeysPage.ADD_CANCEL.getDisplayName()};
        int result = JOptionPane.showOptionDialog(this, cards.view(), NSAppUtil.ApiKeysPage.ADD_DIALOG.getDisplayName(),
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
                    NSAppUtil.ApiKeysPage.MISSING_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (!generating && (appId.isBlank() != domainId.isBlank())) {
            JOptionPane.showMessageDialog(this,
                    "Provide both App ID and Domain ID, or leave both empty.",
                    NSAppUtil.ApiKeysPage.MISSING_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
            return;
        }

        BackgroundTask.runCatching(this, null,
                () -> ctx.session().storeAPIKey(label, description, domainId, appId, key, provider, baseURI, authScheme, headerName, !generating),
                () -> {
                    reloadApiKeys();
                    JOptionPane.showMessageDialog(this, "API key added.");
                });
    }


    /** The add dialog's form and its fields (one object so the dialog and the render harness share it). */
    private static final class AddKeyForm {
        final JPanel panel;
        final JTextField label = GUIUtil.applyProp(textField(""), NSAppUtil.ApiKeysPage.LABEL_FIELD);
        final JTextField description = GUIUtil.applyProp(textField(""), NSAppUtil.ApiKeysPage.DESCRIPTION_FIELD);
        final JPasswordField key = GUIUtil.applyProp(new JPasswordField(28), NSAppUtil.ApiKeysPage.KEY_FIELD);
        final JTextField appID = GUIUtil.applyProp(textField(""), NSAppUtil.ApiKeysPage.APP_ID_FIELD);
        final JTextField domainID = GUIUtil.applyProp(textField(""), NSAppUtil.ApiKeysPage.DOMAIN_ID_FIELD);
        final JTextField baseURI = GUIUtil.applyProp(textField(""), NSAppUtil.ApiKeysPage.BASE_URL_FIELD);
        final JTextField authScheme = GUIUtil.applyProp(textField(""), NSAppUtil.ApiKeysPage.AUTH_SCHEME_FIELD);
        final JTextField headerName = GUIUtil.applyProp(textField(""), NSAppUtil.ApiKeysPage.HEADER_NAME_FIELD);

        AddKeyForm(JComboBox<String> provider) {
            FormPanel form = new FormPanel();
            form.row(title(NSAppUtil.ApiKeysPage.ADD_TITLE), "growx");
            form.row(blockNote(NSAppUtil.ApiKeysPage.ADD_NOTE), "growx, wmin 0");
            form.row(PanelBuilder.sectionHeader(NSAppUtil.ApiKeysPage.SECTION_KEY.getDisplayName()), "growx, gaptop 10");
            form.requiredField(NSAppUtil.ApiKeysPage.LABEL.getDisplayName(), label);
            form.field(NSAppUtil.ApiKeysPage.DESCRIPTION.getDisplayName(), description);
            form.requiredField(NSAppUtil.ApiKeysPage.KEY.getDisplayName(), PanelBuilder.passwordField(key));
            form.row(PanelBuilder.sectionHeader(NSAppUtil.ApiKeysPage.SECTION_SCOPE.getDisplayName()), "growx, gaptop 10");
            form.field(NSAppUtil.ApiKeysPage.APP_ID.getDisplayName(), appID);
            form.field(NSAppUtil.ApiKeysPage.DOMAIN_ID.getDisplayName(), domainID, NSAppUtil.ApiKeysPage.DOMAIN_ID.getDescription());
            form.row(PanelBuilder.sectionHeader(NSAppUtil.ApiKeysPage.SECTION_ENDPOINT.getDisplayName()), "growx, gaptop 10");
            form.field(NSAppUtil.ApiKeysPage.PROVIDER.getDisplayName(), provider, NSAppUtil.ApiKeysPage.PROVIDER.getDescription());
            form.field(NSAppUtil.ApiKeysPage.BASE_URL.getDisplayName(), baseURI);
            panel = new JPanel(new MigLayout("insets 12", "[480!]")); // the note's wrap width
            panel.setOpaque(false);
            panel.add(form, "growx");
        }
    }

    private AddKeyForm newAddKeyForm() {
        inProvider.setEditable(true);
        inProvider.setSelectedItem(null);
        if (inProvider.getEditor().getEditorComponent() instanceof JTextField providerEditor) {
            GUIUtil.applyProp(providerEditor, NSAppUtil.ApiKeysPage.PROVIDER_FIELD);
        }
        return new AddKeyForm(inProvider);
    }

    // ============================ Change password ============================

    /** The change-password card of the Profile page (the stacked form since 2026-10-27; Back returns to the profile card). */
    private JPanel buildChangePassword() {
        JButton submit = UITokens.primary(GUIUtil.applyProp(new JButton(new IconUtil.SaveIcon(16)), NSAppUtil.PasswordEditor.SUBMIT));
        submit.addActionListener(_ -> onChangePassword(submit));

        FormPanel form = new FormPanel();
        form.requiredField(NSAppUtil.PasswordEditor.CURRENT.getDisplayName(), PanelBuilder.passwordField(GUIUtil.applyProp(currentPwd, NSAppUtil.PasswordEditor.CURRENT_FIELD)));
        form.requiredField(NSAppUtil.PasswordEditor.NEW.getDisplayName(), PanelBuilder.passwordField(GUIUtil.applyProp(newPwd, NSAppUtil.PasswordEditor.NEW_FIELD)));
        form.requiredField(NSAppUtil.PasswordEditor.CONFIRM.getDisplayName(), PanelBuilder.passwordField(GUIUtil.applyProp(confirmPwd, NSAppUtil.PasswordEditor.CONFIRM_FIELD)),
                NSAppUtil.PasswordEditor.CONFIRM.getDescription());

        JPanel detail = PanelBuilder.detail(NSAppUtil.PasswordEditor.EDITOR.getDisplayName(),
                () -> profileCards.show("profile"),
                panel -> {
                    panel.add(blockNote(NSAppUtil.PasswordEditor.NOTE), "growx, wmin 0");
                    panel.add(form, "growx, wmin 0");
                    panel.add(submit, "gaptop 12");
                });
        detail.setName(NSAppUtil.PasswordEditor.EDITOR.getName());
        return detail;
    }

    private void onChangePassword(JButton submit) {
        char[] cur = currentPwd.getPassword();
        char[] next = newPwd.getPassword();

        if (!Arrays.equals(next, confirmPwd.getPassword())) {
            JOptionPane.showMessageDialog(this, "New passwords do not match.", NSAppUtil.PasswordEditor.ERROR_DIALOG.getDisplayName(), JOptionPane.ERROR_MESSAGE);
            return;
        }

        BackgroundTask.runCatching(this, submit,
                () -> ctx.session().changePassword(cur, next),
                () -> {
                    JOptionPane.showMessageDialog(this, "Password changed.");
                    currentPwd.setText("");
                    newPwd.setText("");
                    confirmPwd.setText("");
                    profileCards.show("profile");
                    passwordSection.refresh();
                });
    }

    // ============================ Edit API key ============================

    private JPanel buildEditAPIKey() {

        // save api key button
        JButton submit = GUIUtil.applyProp(new JButton(new IconUtil.SaveIcon(16)), NSAppUtil.ApiKeysPage.SAVE);

        rotateKey.addActionListener(_ -> onRotateAPIKey(rotateKey));

        // copy api key button
        JButton copyKey = GUIUtil.applyProp(GUIUtil.iconButton(new IconUtil.CopyIcon(16)), NSAppUtil.ApiKeysPage.COPY_KEY);
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
        form.row(PanelBuilder.sectionHeader(NSAppUtil.ApiKeysPage.SECTION_KEY.getDisplayName()), "growx");
        form.requiredField(NSAppUtil.ApiKeysPage.LABEL.getDisplayName(), GUIUtil.applyProp(editKeyLabel, NSAppUtil.ApiKeysPage.LABEL_EDIT_FIELD));
        form.field(NSAppUtil.ApiKeysPage.DESCRIPTION.getDisplayName(), GUIUtil.applyProp(editKeyDescription, NSAppUtil.ApiKeysPage.DESCRIPTION_EDIT_FIELD));
        form.requiredField(NSAppUtil.ApiKeysPage.EDIT_KEY.getDisplayName(), GUIUtil.applyProp(keyView, NSAppUtil.ApiKeysPage.EDIT_KEY), NSAppUtil.ApiKeysPage.EDIT_KEY.getDescription());
        form.row(PanelBuilder.sectionHeader(NSAppUtil.ApiKeysPage.SECTION_SCOPE.getDisplayName()), "growx, gaptop 10");
        form.field(NSAppUtil.ApiKeysPage.APP_ID.getDisplayName(), GUIUtil.applyProp(keyAppID, NSAppUtil.ApiKeysPage.APP_ID_EDIT_FIELD));
        form.field(NSAppUtil.ApiKeysPage.DOMAIN_ID.getDisplayName(), GUIUtil.applyProp(keyDomainID, NSAppUtil.ApiKeysPage.DOMAIN_ID_EDIT_FIELD), NSAppUtil.ApiKeysPage.DOMAIN_ID.getDescription());
        form.row(PanelBuilder.sectionHeader(NSAppUtil.ApiKeysPage.SECTION_ENDPOINT.getDisplayName()), "growx, gaptop 10");
        form.field(NSAppUtil.ApiKeysPage.PROVIDER.getDisplayName(), GUIUtil.applyProp(keyProvider, NSAppUtil.ApiKeysPage.PROVIDER), NSAppUtil.ApiKeysPage.PROVIDER.getDescription());
        form.field(NSAppUtil.ApiKeysPage.BASE_URL.getDisplayName(), GUIUtil.applyProp(keyURI, NSAppUtil.ApiKeysPage.BASE_URL_EDIT_FIELD));

        JButton deleteKey = GUIUtil.applyProp(new JButton(new IconUtil.DeleteIcon(16)), NSAppUtil.ApiKeysPage.DELETE);
        deleteKey.addActionListener(_ -> onDeleteAPIKey(selectedKey));
        JPanel actions = new JPanel(new MigLayout("insets 0, gapx 8"));
        actions.setOpaque(false);
        actions.add(submit);
        actions.add(deleteKey);

        JPanel detail = PanelBuilder.detail(NSAppUtil.ApiKeysPage.EDITOR.getDisplayName(),
                () -> showKeyDetail(selectedKeyRow()),
                panel -> {
                    panel.add(form, "growx, wmin 0");
                    panel.add(actions, "gaptop 12");
                }
        );
        detail.setName(NSAppUtil.ApiKeysPage.EDITOR.getName());
        return detail;
    }

    private void onEditAPIKey(SubjectAPIKey key) {
        selectedKey = key;

        // External (third-party) keys aren't issued by us, so they can't be rotated.
        boolean external = ctx.session().isExternalKey(key);
        rotateKey.setEnabled(!external);
        rotateKey.setToolTipText(external ? NSAppUtil.ApiKeysPage.ROTATE_EXTERNAL.getDescription() : NSAppUtil.ApiKeysPage.ROTATE.getDescription());

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
        showKey.setToolTipText(masked ? NSAppUtil.ApiKeysPage.SHOW_KEY.getDescription() : NSAppUtil.ApiKeysPage.HIDE_KEY.getDescription());
        isKeyShown = !masked;
    }

    private void onEditAPIDetails(JButton submit) {
        String label = editKeyLabel.getText().trim();
        String description = editKeyDescription.getText().trim();

        if (label.isBlank()) {
            JOptionPane.showMessageDialog(this,
                    "Label is required.",
                    NSAppUtil.ApiKeysPage.MISSING_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
            return;
        }

        String appID = keyAppID.getText().trim();
        String domainID = keyDomainID.getText().trim();
        if (appID.isBlank() != domainID.isBlank()) {
            JOptionPane.showMessageDialog(this,
                    "Provide both App ID and Domain ID, or leave both empty.",
                    NSAppUtil.ApiKeysPage.MISSING_DIALOG.getDisplayName(), JOptionPane.WARNING_MESSAGE);
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
                    reloadApiKeys();
                });
    }

    private void onRotateAPIKey(JButton src) {
        if (selectedKey == null) return;
        int ok = JOptionPane.showConfirmDialog(this,
                "Rotate this key? The current secret stops working immediately.",
                NSAppUtil.ApiKeysPage.ROTATE_DIALOG.getDisplayName(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        BackgroundTask.runCatching(this, src,
                () -> ctx.session().rotateAPIKey(selectedKey),
                () -> {
                    // rotate mutates selectedKey in place; re-populate so the new secret shows.
                    onEditAPIKey(selectedKey);
                    reloadApiKeys();
                    JOptionPane.showMessageDialog(this, "Key rotated. Copy the new secret now.");
                });
    }

    private void onDeleteAPIKey(SubjectAPIKey key) {
        if (key == null) return;
        int ok = JOptionPane.showConfirmDialog(this,
                deleteConfirm(key.getName(), "API key"),
                NSAppUtil.ApiKeysPage.DELETE_DIALOG.getDisplayName(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;

        BackgroundTask.runCatching(this, null,
                () -> ctx.session().deleteAPIKey(key),
                () -> {
                    if (selectedKey == key) {
                        selectedKey = null;
                        editKeySecret.setText("");
                    }
                    apiKeyTable.clearSelection();
                    reloadApiKeys();
                    JOptionPane.showMessageDialog(this, "API key Deleted.");
                });
    }
}
