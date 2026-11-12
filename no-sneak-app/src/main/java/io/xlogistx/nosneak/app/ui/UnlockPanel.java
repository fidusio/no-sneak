package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.BadgeLabel;
import io.xlogistx.gui.DirectoryField;
import io.xlogistx.gui.FontSizeWidget;
import io.xlogistx.gui.FormPanel;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.InlineMessage;
import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.gui.ScrollablePanel;
import io.xlogistx.gui.SplashSidePanel;
import io.xlogistx.gui.StepperPanel;
import io.xlogistx.gui.UIFontSize;
import io.xlogistx.gui.UITokens;
import io.xlogistx.gui.WrapLabel;
import io.xlogistx.nosneak.app.NSAppUtil;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.app.ui.utility.AppPrefs;
import io.xlogistx.nosneak.app.ui.utility.Session;
import io.xlogistx.nosneak.app.NSAppUtil.SignInForm;
import io.xlogistx.nosneak.app.NSAppUtil.UnlockPage;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import java.awt.*;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

/**
 * The screen the application shows until a subject is signed in (2026-10-24): a brand panel on
 * the left and one card with two steps on the right.
 * <ol>
 *   <li><b>Open store</b> — the installation directory (the last successful one pre-filled from
 *       {@link AppPrefs#storeLocation()}) and its vault password. When the directory holds no
 *       vault the step grows the first-run rows — the operator's account (the store's super-admin)
 *       and the database settings — and the button reads <i>Create</i>; otherwise <i>Open</i>.
 *       Every input carries a tooltip and a warning row under the vault password says it is not
 *       recoverable ({@link Form#VAULT_PASSWORD_WARNING}, 2026-10-29). Every label, tooltip and
 *       button text is a constant of {@link UnlockPage} / {@link SignInForm} (2026-11-01).
 *       Enter in the vault password field is the click. The work runs off the EDT through the
 *       injected {@link StoreOpener} ({@code NoSneakStore.openOrCreate} in production); a failure
 *       (wrong vault password, an installation from before the 2026-10-21 model) stays on the step
 *       as an inline message. Success completes the step, remembers the location, hands the
 *       manager to {@code onStoreOpened} and activates step 2. Once completed the step is fixed
 *       for the life of the process, as the store itself is.</li>
 *   <li><b>Sign in</b> — username and password against the {@link Session} bound with
 *       {@link #bindSession}; <i>Create another account in this store</i> flips the step into
 *       register mode (confirm password, the password rules checked first, "already taken"
 *       reported inline). A successful sign-in shows nothing here: the frame listens to the
 *       session's {@code authenticated} event and swaps this panel out.</li>
 * </ol>
 * The pure decisions (open or create, what each step requires) live in {@link Form} so they can
 * be tested without a display. What was dropped from the previous screens: the DomainAppID combo
 * ({@code Session.loginUsernamePassword} takes no domain) and the passkey placeholder.
 */
public class UnlockPanel extends JPanel {

    /** Opens or creates the installation; runs off the EDT and may throw with the reason. */
    @FunctionalInterface
    public interface StoreOpener {
        ShiroDSDomainSecurityManager open(String location, char[] vaultPassword, NoSneakStore.FirstRun firstRun) throws Exception;
    }

    /** The two steps' decisions, free of Swing. */
    public static final class Form {
        public static final String CREATE_HINT = "No vault here: a new vault, database and operator account will be created.";
        public static final String OPEN_HINT = "Existing vault found: enter its password.";
        /**
         * Shown under the vault password field on every run and in its tooltip (2026-10-29): the
         * vault password is the one secret nothing can bring back.
         */
        public static final String VAULT_PASSWORD_WARNING = UnlockPage.VAULT_PASSWORD_WARNING.getDisplayName();

        private Form() {
        }

        /** True when the directory is set and holds no vault, so the step creates. */
        public static boolean creates(String location) {
            return !SUS.isEmpty(location) && !NoSneakStore.vaultExists(location);
        }

        /** The hint under the location, or null when no location is chosen. */
        public static String storeHint(String location) {
            if (SUS.isEmpty(location)) return null;
            return creates(location) ? CREATE_HINT : OPEN_HINT;
        }

        /**
         * What stops step 1 from running, or null when it may.
         *
         * @param create whether the step creates (then the operator rows are required)
         */
        public static String validateStore(String location, char[] vaultPassword, boolean create,
                                           String operator, char[] operatorPassword, char[] operatorConfirm) {
            if (SUS.isEmpty(location)) return "Please choose a location.";
            if (vaultPassword == null || vaultPassword.length == 0) return "The vault password is required.";
            if (create) {
                if (SUS.isEmpty(operator) || operatorPassword == null || operatorPassword.length == 0)
                    return "The operator's username and password are required to create the store.";
                if (!Arrays.equals(operatorPassword, operatorConfirm)) return "The operator passwords do not match.";
                String rule = passwordRuleFailure(operatorPassword);
                if (rule != null) return "Operator password: " + rule;
            }
            return null;
        }

        /** What stops a sign-in, or null. */
        public static String validateSignIn(String username, char[] password) {
            if (SUS.isEmpty(username) || password == null || password.length == 0)
                return "Username and password are required.";
            return null;
        }

        /** What stops a registration, or null: blank fields, a mismatch, then the password rules. */
        public static String validateRegister(String username, char[] password, char[] confirm) {
            if (SUS.isEmpty(username)) return "A username is required.";
            if (password == null || password.length == 0) return "A password is required.";
            if (!Arrays.equals(password, confirm)) return "Passwords do not match.";
            return passwordRuleFailure(password);
        }

        /** The password filter's reason for refusing {@code password}, or null when it passes. */
        public static String passwordRuleFailure(char[] password) {
            String candidate = new String(password);
            if (FilterType.PASSWORD.isValid(candidate)) return null;
            try {
                FilterType.PASSWORD.validate(candidate);
            } catch (Exception ex) {
                if (ex.getMessage() != null && !ex.getMessage().isBlank()) return ex.getMessage();
            }
            return "Password does not meet requirements.";
        }
    }

    private static final String FIRST_RUN = "firstRun";
    private static final String REGISTER = "register";

    private final StoreOpener opener;
    private final Consumer<ShiroDSDomainSecurityManager> onStoreOpened;
    private Session session;

    private final StepperPanel steps = new StepperPanel();
    private final int stepOpen;
    private final int stepSign;
    private boolean storeOpen;

    // step 1
    // step-1 tooltips (2026-10-29) are the *_FIELD descriptions of UnlockPage, hovered on the field itself
    private final DirectoryField location = GUIUtil.applyProp(new DirectoryField(), UnlockPage.LOCATION_FIELD);
    private final JPasswordField vaultPassword = GUIUtil.applyProp(new JPasswordField(20), UnlockPage.VAULT_PASSWORD_FIELD);
    private final InlineMessage storeMessage = new InlineMessage();
    /**
     * Why the store could not be opened, wrapped at the form's width and hidden while empty
     * (2026-11-12, the maintainer: "catch datastore open issues as when it fail the login window
     * gets crooked"). A data store failure is a sentence or several, with a path in it; in the
     * one-line message above it made the form as wide as the sentence.
     */
    private final WrapLabel storeFailure = GUIUtil.applyProp(new WrapLabel(""), UnlockPage.STORE_FAILURE);
    private final FormPanel storeForm = GUIUtil.applyProp(new FormPanel(), UnlockPage.STORE_FORM);
    private final JTextField operatorID = GUIUtil.applyProp(PanelBuilder.textField("", 20), UnlockPage.OPERATOR_FIELD);
    private final JPasswordField operatorPassword = GUIUtil.applyProp(new JPasswordField(20), UnlockPage.OPERATOR_PASSWORD_FIELD);
    private final JPasswordField operatorConfirm = GUIUtil.applyProp(new JPasswordField(20), UnlockPage.OPERATOR_CONFIRM_FIELD);
    private final JTextField dbUser = GUIUtil.applyProp(PanelBuilder.textField(NoSneakStore.DEFAULT_DB_USER, 20), UnlockPage.DB_USER_FIELD);
    private final JPasswordField dbPassword = GUIUtil.applyProp(new JPasswordField(20), UnlockPage.DB_PASSWORD_FIELD);
    private final JPasswordField dbEncryptionPassword = GUIUtil.applyProp(new JPasswordField(20), UnlockPage.DB_ENCRYPTION_FIELD);
    private final JButton openButton = UITokens.primary(GUIUtil.applyProp(new JButton(), UnlockPage.OPEN));
    /** Component names of the text size row (2026-11-03), for tests: the control and its Reset. */
    public static final String TEXT_SIZE = UnlockPage.TEXT_SIZE.getName();
    public static final String TEXT_SIZE_RESET = UnlockPage.TEXT_SIZE_RESET.getName();

    // step 2
    private final JTextField username = GUIUtil.applyProp(new JTextField(20), SignInForm.USERNAME_FIELD);
    private final JPasswordField password = GUIUtil.applyProp(new JPasswordField(20), SignInForm.PASSWORD_FIELD);
    private final JPasswordField confirmPassword = GUIUtil.applyProp(new JPasswordField(20), SignInForm.CONFIRM_FIELD);
    private final FormPanel signForm = GUIUtil.applyProp(new FormPanel(), SignInForm.FORM);
    private final InlineMessage signMessage = new InlineMessage();
    private final JButton signButton = UITokens.primary(GUIUtil.applyProp(new JButton(), SignInForm.SIGN_IN));
    private final JButton modeToggle = UITokens.link(new JButton());
    private boolean registering;

    /**
     * @param opener        opens or creates the store from the step-1 answers (off the EDT)
     * @param onStoreOpened receives the open manager on the EDT, before step 2 is activated; the
     *                      host builds the application around it and calls {@link #bindSession}
     */
    public UnlockPanel(StoreOpener opener, Consumer<ShiroDSDomainSecurityManager> onStoreOpened) {
        super(new MigLayout("insets 0, gap 0, fill, hidemode 3", "[400::520,fill][grow,fill]", "[grow,fill]"));
        this.opener = opener;
        this.onStoreOpened = onStoreOpened;
        setName(UnlockPage.PAGE.getName());

        add(buildSplash(), "growy");
        add(buildRight(), "grow");

        stepOpen = steps.addStep(UnlockPage.STEP_OPEN.getDisplayName(), UnlockPage.STEP_OPEN.getDescription(), buildOpenStep());
        stepSign = steps.addStep(UnlockPage.STEP_SIGN_IN.getDisplayName(), UnlockPage.STEP_SIGN_IN.getDescription(), buildSignStep());
        steps.setStepEnabled(stepSign, false);

        File last = AppPrefs.storeLocation();
        if (last != null) {
            location.setDirectory(last);
            // a returning subject only types the vault password: the caret starts there
            addAncestorListener(new AncestorListener() {
                public void ancestorAdded(AncestorEvent e) {
                    if (!storeOpen) vaultPassword.requestFocusInWindow();
                }

                public void ancestorRemoved(AncestorEvent e) {
                }

                public void ancestorMoved(AncestorEvent e) {
                }
            });
        }
        applyStoreMode(path());
        applySignMode();
    }

    // ---- building ----

    /**
     * The left half of the sign-in window: the same promises as the About card and the Help
     * (2026-10-27 — tagline from {@link MenuBarFactory#TAGLINE}; keep the three points in step
     * with the Help's "What it will and won't do" / "Your data stays yours"). The footer keeps
     * the Java and platform facts because About is not reachable before sign-in.
     */
    private JComponent buildSplash() {
        List<String> points = List.of(
                UnlockPage.SPLASH_POINT_SCANS.getDisplayName(),
                UnlockPage.SPLASH_POINT_STORE.getDisplayName(),
                UnlockPage.SPLASH_POINT_ASSISTANT.getDisplayName());
        String footer = NoSneakMain.VERSION.getName() + " " + NoSneakMain.VERSION.version()
                + " · Java " + System.getProperty("java.version")
                + " · " + System.getProperty("os.name") + " " + System.getProperty("os.arch");
        return new SplashSidePanel(
                IconUtil.svgIcon("io/xlogistx/gui/icons/shield.svg", 26, new Color(0xA9A8F0)),
                UnlockPage.SPLASH_BRAND.getDisplayName(),
                UnlockPage.SPLASH_TITLE.getDisplayName(),
                MenuBarFactory.TAGLINE + ". " + UnlockPage.SPLASH_TAGLINE.getDisplayName(),
                points, footer);
    }

    private JComponent buildRight() {
        Color ground = UITokens.ground();

        JPanel card = new JPanel(new MigLayout("insets 32 36 28 36, fillx, wrap 1, gapy 0", "[grow,fill]"));
        card.setBackground(UITokens.surface());
        card.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        card.add(steps, "growx");

        WrapLabel text = GUIUtil.applyProp(new WrapLabel(""), UnlockPage.FIRST_RUN_NOTE);
        text.setFont(UITokens.font(Font.PLAIN, -1f));
        card.add(callout(new IconUtil.InfoIcon(16), text, ground), "growx, gaptop 16");

        // the card sits centred in the free space and scrolls only when the window is shorter than it
        ScrollablePanel centre = new ScrollablePanel(new MigLayout("insets 40 24 40 24, fill", "[grow,center]", "[grow,center]"));
        centre.setBackground(ground);
        centre.add(card, "wmin 420, wmax 560, growx");

        JScrollPane scroll = new JScrollPane(centre, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(ground);

        // the text size row sits above the scrolling area, so it is on screen whatever the window's height
        JPanel right = new JPanel(new BorderLayout());
        right.setBackground(ground);
        right.add(scroll, BorderLayout.CENTER);
        right.add(buildTextSizeRow(ground), BorderLayout.NORTH);
        return right;
    }

    /**
     * The text size row (2026-11-03; the maintainer: "at start sometimes it is too small"): the
     * same control as the Settings page's Appearance block — gui-audio's {@link FontSizeWidget}
     * over {@link UIFontSize} with its own caption and Reset link ({@code withLabel().withReset()},
     * 2026-11-06) — right-aligned in the right pane's top corner, so
     * a subject whose stored size reads too small on this screen can fix it before signing in.
     * The size applies at once to the whole application and is remembered through the listener
     * {@code NoSneakMain} registers on {@code UIFontSize}, like a change made in Settings.
     */
    private JComponent buildTextSizeRow(Color ground) {
        FontSizeWidget size = GUIUtil.applyProp(new FontSizeWidget().withLabel().withReset(), UnlockPage.TEXT_SIZE);
        GUIUtil.applyProp(size.getLabel(), UnlockPage.TEXT_SIZE_LABEL).setForeground(UITokens.muted());
        GUIUtil.applyProp(size.getResetButton(), UnlockPage.TEXT_SIZE_RESET);
        JPanel row = new JPanel(new MigLayout("insets 12 24 0 24", "[grow][]"));
        row.setBackground(ground);
        row.add(new JLabel(), "growx");
        row.add(size);
        return row;
    }

    /**
     * A tinted row with an icon on the left and wrapping text beside it: the first-run note under
     * the card and the vault password warning in step 1. The text wraps at the row's real width.
     */
    private static JPanel callout(Icon icon, WrapLabel text, Color background) {
        JPanel row = new JPanel(new MigLayout("insets 12 14 12 14", "[]10[grow,fill]")) {
            @Override
            public void doLayout() {
                text.setWrapWidth(getWidth() - 14 - 14 - icon.getIconWidth() - 10);
                super.doLayout();
            }
        };
        row.setBackground(background);
        row.add(new JLabel(icon), "aligny top, gaptop 2");
        row.add(text, "growx, wmin 0");
        return row;
    }

    /** Sets the installation directory as if chosen through the field; for hosts and tests. */
    public void setLocation(File directory) {
        location.setDirectory(directory);
        applyStoreMode(path());
    }

    private JComponent buildOpenStep() {
        location.dialogTitle(UnlockPage.LOCATION_DIALOG.getDisplayName())
                .placeholder(UnlockPage.LOCATION_PLACEHOLDER.getDisplayName())
                .startDirectory(() -> {
                    File last = AppPrefs.storeLocation();
                    return last != null ? last : new File(System.getProperty("user.home"));
                });
        location.onChange(_ -> applyStoreMode(path()));

        // the field itself carries the tooltip (applied with its descriptor); the path field inside it says the same
        location.getPathField().setToolTipText(UnlockPage.LOCATION_FIELD.getDescription());
        GUIUtil.applyProp(location.getChooseButton(), UnlockPage.LOCATION_CHOOSE);

        storeForm.field(UnlockPage.LOCATION.getDisplayName(), location);
        storeForm.row(storeMessage, "growx, gaptop 4");
        storeForm.requiredField(UnlockPage.VAULT_PASSWORD.getDisplayName(), PanelBuilder.passwordField(vaultPassword),
                UnlockPage.VAULT_PASSWORD_HINT.getDisplayName());
        // the warning stands out from the muted hints: bold, in the warning colour, on its own tinted row
        WrapLabel warning = GUIUtil.applyProp(new WrapLabel(""), UnlockPage.VAULT_PASSWORD_WARNING);
        warning.setFont(UITokens.font(Font.BOLD, -1f));
        warning.setForeground(UITokens.warn());
        storeForm.row(callout(IconUtil.svgIcon("io/xlogistx/gui/icons/alert.svg", 16, UITokens.warn()), warning, UITokens.warnSoft()),
                "growx, gaptop 6");
        storeForm.group(FIRST_RUN, () -> {
            storeForm.requiredField(UnlockPage.OPERATOR.getDisplayName(), operatorID, UnlockPage.OPERATOR_FIELD.getDescription());
            storeForm.requiredField(UnlockPage.OPERATOR_PASSWORD.getDisplayName(), PanelBuilder.passwordField(operatorPassword));
            storeForm.requiredField(UnlockPage.OPERATOR_CONFIRM.getDisplayName(), PanelBuilder.passwordField(operatorConfirm));
            storeForm.field(UnlockPage.DB_USER.getDisplayName(), dbUser);
            storeForm.field(UnlockPage.DB_PASSWORD.getDisplayName(), PanelBuilder.passwordField(dbPassword), UnlockPage.DB_GENERATED_HINT.getDisplayName());
            storeForm.field(UnlockPage.DB_ENCRYPTION.getDisplayName(), PanelBuilder.passwordField(dbEncryptionPassword), UnlockPage.DB_GENERATED_HINT.getDisplayName());
        });

        storeFailure.setFont(UITokens.font(Font.PLAIN, -1f));
        storeFailure.setForeground(UITokens.danger());
        storeFailure.setVisible(false);
        storeForm.row(storeFailure, "growx, wmin 0, gaptop 6");
        // the reason wraps at the width the form has, so it makes the form taller, never wider
        storeForm.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                storeFailure.setWrapWidth(storeForm.getWidth());
            }
        });

        JPanel actions = new JPanel(new MigLayout("insets 0", "[grow][]"));
        actions.setOpaque(false);
        actions.add(new JLabel(), "growx");
        actions.add(openButton);
        storeForm.row(actions, "growx, gaptop 12");

        openButton.addActionListener(_ -> onOpenStore());
        vaultPassword.addActionListener(_ -> openButton.doClick());
        return storeForm;
    }

    private JComponent buildSignStep() {
        signForm.field(SignInForm.USERNAME.getDisplayName(), username);
        signForm.field(SignInForm.PASSWORD.getDisplayName(), PanelBuilder.passwordField(password));
        signForm.group(REGISTER, () -> signForm.field(SignInForm.CONFIRM.getDisplayName(), PanelBuilder.passwordField(confirmPassword)));
        signForm.row(signMessage, "growx, gaptop 4");

        JPanel actions = new JPanel(new MigLayout("insets 0, gapx 12", "[grow][]"));
        actions.setOpaque(false);
        actions.add(modeToggle, "alignx left");
        actions.add(signButton);
        signForm.row(actions, "growx, gaptop 10");

        modeToggle.addActionListener(_ -> {
            registering = !registering;
            applySignMode();
        });
        signButton.addActionListener(_ -> onSign());
        username.addActionListener(_ -> password.requestFocusInWindow());
        password.addActionListener(_ -> signButton.doClick());
        confirmPassword.addActionListener(_ -> signButton.doClick());
        return signForm;
    }

    // ---- step 1 ----

    private String path() {
        File dir = location.getDirectory();
        return dir != null ? dir.getAbsolutePath() : null;
    }

    /** Shows the first-run rows when the chosen directory has no vault, and names the button after the work. */
    private void applyStoreMode(String path) {
        boolean create = Form.creates(path);
        storeForm.showGroup(FIRST_RUN, create);
        GUIUtil.applyProp(openButton, create ? UnlockPage.CREATE : UnlockPage.OPEN);
        String hint = Form.storeHint(path);
        if (hint != null) storeMessage.info(hint);
        else storeMessage.clear();
    }

    private void onOpenStore() {
        if (storeOpen) return;
        String path = path();
        boolean create = Form.creates(path); // the directory may have changed since it was chosen
        applyStoreMode(path);

        char[] vault = vaultPassword.getPassword();
        String operator = operatorID.getText().trim();
        char[] opPwd = operatorPassword.getPassword();
        char[] opConfirm = operatorConfirm.getPassword();
        String problem = Form.validateStore(path, vault, create, operator, opPwd, opConfirm);
        Arrays.fill(opConfirm, '\0');
        if (problem != null) {
            storeMessage.error(problem);
            Arrays.fill(vault, '\0');
            Arrays.fill(opPwd, '\0');
            return;
        }
        NoSneakStore.FirstRun firstRun = create
                ? new NoSneakStore.FirstRun(operator, opPwd, dbUser.getText().trim(),
                new String(dbPassword.getPassword()), new String(dbEncryptionPassword.getPassword()))
                : null;
        storeMessage.info(create ? "Creating the vault, the database and the operator account…" : "Opening the store…");
        showStoreFailure(null);

        BackgroundTask.run(this, openButton, () -> {
            try {
                ShiroDSDomainSecurityManager dsm = opener.open(path, vault, firstRun);
                AppPrefs.storeLocation(path);
                return (Object) dsm;
            } catch (Throwable e) {
                // everything, an Error included (a missing class, a driver's static initialiser):
                // whatever stops the store from opening is reported under the form, never thrown
                // out of the worker with the window left as it was
                return e;
            } finally {
                Arrays.fill(vault, '\0');
                Arrays.fill(opPwd, '\0');
            }
        }, result -> {
            if (result instanceof Throwable e) {
                e.printStackTrace(); // the whole chain for the log; the screen shows the reason
                storeMessage.error(create ? "The store could not be created." : "The store could not be opened.");
                showStoreFailure(storeFailureReason(e));
                vaultPassword.requestFocusInWindow();
                return;
            }
            ShiroDSDomainSecurityManager dsm = (ShiroDSDomainSecurityManager) result;
            try {
                // the host builds the application on the store here; a failure is the host's to
                // undo (it closes the store), the screen stays on step 1 and says why
                onStoreOpened.accept(dsm);
            } catch (RuntimeException | Error e) {
                storeMessage.error("The store opened, but the application could not start on it.");
                showStoreFailure(storeFailureReason(e));
                return;
            }
            clearStoreSecrets();
            markStoreOpened(path);
        });
    }

    private static String reason(Exception e) {
        String m = e.getMessage();
        return m != null && !m.isBlank() ? m : e.getClass().getSimpleName();
    }

    /** Shows (or with null hides) the wrapped reason under the store form. */
    private void showStoreFailure(String reason) {
        storeFailureReason = reason != null ? reason : "";
        storeFailure.setText(breakLongWords(storeFailureReason));
        storeFailure.setVisible(reason != null);
        storeFailure.setWrapWidth(storeForm.getWidth());
        revalidate();
        repaint();
    }

    /** The reason under the store form, or empty; for tests. */
    public String getStoreFailure() {
        return storeFailure.isVisible() ? storeFailureReason : "";
    }

    /** The reason as it was given; the label holds it with its long paths broken. */
    private String storeFailureReason = "";

    /** The longest run of characters the label is given without a place to wrap. */
    static final int WORD_MAX = 40;

    /**
     * A file path has no space in it, and a word the label cannot wrap is cut at the form's
     * edge. A word longer than {@link #WORD_MAX} gets a line break after a {@code \} or a
     * {@code /} once that many characters have run (or right there when it has none), so the
     * whole path is readable over two or three lines.
     */
    static String breakLongWords(String text) {
        StringBuilder out = new StringBuilder(text.length() + 8);
        int run = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            out.append(c);
            if (Character.isWhitespace(c)) {
                run = 0;
                continue;
            }
            run++;
            boolean separator = c == '\\' || c == '/';
            if (i + 1 < text.length() && !Character.isWhitespace(text.charAt(i + 1))
                    && ((run >= WORD_MAX && separator) || run >= WORD_MAX * 2)) {
                out.append('\n');
                run = 0;
            }
        }
        return out.toString();
    }

    /** The one-line message under the location field, or empty; for tests. */
    public String getStoreMessage() {
        return storeMessage.hasMessage() ? storeMessage.getText() : "";
    }

    /** The longest reason shown; a driver's message can carry a whole statement. */
    static final int FAILURE_MAX = 400;

    /**
     * What to tell the operator when the store does not open: a plain sentence for the failures
     * a data store commonly has (the file held by another program, the credentials refused, a
     * damaged file), otherwise the deepest cause's own message, on its first line and at most
     * {@link #FAILURE_MAX} characters, cut at a word. The whole chain is searched, since the
     * connection pool wraps the driver's exception.
     */
    static String storeFailureReason(Throwable failure) {
        StringBuilder all = new StringBuilder();
        Throwable deepest = failure;
        java.util.Set<Throwable> seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        for (Throwable t = failure; t != null && seen.add(t); t = t.getCause()) {
            deepest = t;
            if (t.getMessage() != null) all.append(t.getMessage()).append('\n');
        }
        String text = all.toString().toLowerCase(java.util.Locale.ROOT);
        if (text.contains("already in use") || text.contains("locked by another process") || text.contains("90020")) {
            return "The database file is in use by another program, most likely another NoSneak window on this store. Close it, then open the store again.";
        }
        if (text.contains("wrong user name or password") || text.contains("28000")) {
            return "The database refused the user name and password kept in the vault. The vault and the database in this directory do not belong together.";
        }
        if (text.contains("encryption error") || text.contains("90049")) {
            return "The database could not be decrypted with the encryption password kept in the vault. The vault and the database in this directory do not belong together.";
        }
        if (text.contains("file corrupted") || text.contains("90030")) {
            return "The database file is damaged and could not be read. Restore it from a backup.";
        }
        String m = failure.getMessage();
        if (m == null || m.isBlank()) m = deepest.getMessage();
        if (m == null || m.isBlank()) return "The reason was not given (" + deepest.getClass().getName() + ").";
        m = m.strip();
        int line = m.indexOf('\n');
        if (line > 0) m = m.substring(0, line).strip();
        if (m.length() > FAILURE_MAX) {
            int cut = m.lastIndexOf(' ', FAILURE_MAX);
            m = m.substring(0, cut > 0 ? cut : FAILURE_MAX) + " (the rest is in the log)";
        }
        return m;
    }

    private void clearStoreSecrets() {
        vaultPassword.setText("");
        operatorPassword.setText("");
        operatorConfirm.setText("");
        dbPassword.setText("");
        dbEncryptionPassword.setText("");
    }

    /**
     * Step 1 is done — the store at {@code path} is open. Called by the panel itself after a
     * successful Open / Create, and by the host when the store was opened from launch parameters.
     * Idempotent.
     */
    public void markStoreOpened(String path) {
        if (storeOpen) return;
        storeOpen = true;
        storeMessage.clear();
        steps.complete(stepOpen, (path != null ? path : "") + " · " + UnlockPage.VAULT_UNLOCKED.getDisplayName(), null);
        steps.setStepEnabled(stepSign, true);
        steps.activate(stepSign);
        SwingUtilities.invokeLater(username::requestFocusInWindow);
    }

    /** True once step 1 has completed. */
    public boolean isStoreOpen() {
        return storeOpen;
    }

    // ---- step 2 ----

    /** Gives step 2 the session it signs into. The host calls this from {@code onStoreOpened}. */
    public void bindSession(Session session) {
        this.session = session;
    }

    /**
     * Signs in as if the subject had typed the credentials and pressed <i>Sign in</i> (2026-10-25,
     * for the {@code subject=} + {@code password=} launch parameters): the fields are filled so a
     * failure shows inline under them with the username kept, and success swaps the panel out
     * through the host's authenticated listener as usual. Needs the store open and the session
     * bound; otherwise the inline message says so. The password array is wiped here.
     */
    public void signIn(String user, char[] pwd) {
        registering = false;
        applySignMode();
        username.setText(user != null ? user : "");
        password.setText(pwd != null ? new String(pwd) : "");
        if (pwd != null) Arrays.fill(pwd, '\0');
        onSign();
    }

    /** The inline message under the sign-in fields, or empty; for tests. */
    public String getSignMessage() {
        return signMessage.hasMessage() ? signMessage.getText() : "";
    }

    /** A neutral note under the sign-in fields; the host shows one while it loads after a login. */
    public void signInfo(String text) {
        signMessage.info(text);
    }

    private void applySignMode() {
        signForm.showGroup(REGISTER, registering);
        GUIUtil.applyProp(signButton, registering ? SignInForm.REGISTER : SignInForm.SIGN_IN);
        GUIUtil.applyProp(modeToggle, registering ? SignInForm.TO_SIGN_IN : SignInForm.TO_REGISTER);
        signMessage.clear();
        if (!registering) confirmPassword.setText("");
    }

    private void onSign() {
        if (session == null) {
            signMessage.error("Open the store first.");
            return;
        }
        String user = username.getText().trim();
        char[] pwd = password.getPassword();
        if (registering) {
            char[] confirm = confirmPassword.getPassword();
            String problem = Form.validateRegister(user, pwd, confirm);
            Arrays.fill(confirm, '\0');
            if (problem != null) {
                signMessage.error(problem);
                Arrays.fill(pwd, '\0');
                return;
            }
            signMessage.info("Registering…");
            BackgroundTask.run(this, signButton, () -> attempt(() -> session.registerUsernamePassword(user, pwd), pwd), failure -> {
                if (failure != null) {
                    signMessage.error(failure);
                    return;
                }
                password.setText("");
                confirmPassword.setText("");
                registering = false;
                applySignMode();
                signMessage.ok("Registered successfully. Sign in with the new account.");
                password.requestFocusInWindow();
            });
        } else {
            String problem = Form.validateSignIn(user, pwd);
            if (problem != null) {
                signMessage.error(problem);
                Arrays.fill(pwd, '\0');
                return;
            }
            signMessage.info("Signing in…");
            BackgroundTask.run(this, signButton, () -> attempt(() -> session.loginUsernamePassword(user, pwd), pwd), failure -> {
                if (failure != null) {
                    signMessage.error(failure);
                    password.setText("");
                    password.requestFocusInWindow();
                }
                // success shows nothing: the host swaps this panel out on the authenticated event
            });
        }
    }

    @FunctionalInterface
    private interface SessionCall {
        void run() throws AccessSecurityException;
    }

    /** Runs a session call; an access failure comes back as its message, anything else propagates to the dialog. */
    private static String attempt(SessionCall call, char[] secret) {
        try {
            call.run();
            return null;
        } catch (AccessSecurityException e) {
            return reason(e);
        } finally {
            Arrays.fill(secret, '\0');
        }
    }

    /**
     * After a logout: step 1 stays done (the store stays open for the process), step 2 forgets
     * everything the previous subject typed and takes the focus again.
     */
    public void resetForSignIn() {
        registering = false;
        username.setText("");
        password.setText("");
        confirmPassword.setText("");
        applySignMode();
        if (storeOpen) {
            steps.activate(stepSign);
            SwingUtilities.invokeLater(username::requestFocusInWindow);
        }
    }

    /** A pill the host may show beside the store once it is open; here for the frame's title bar or footer. */
    public static BadgeLabel vaultBadge() {
        return GUIUtil.applyProp(new BadgeLabel("", IconUtil.svgIcon("io/xlogistx/gui/icons/lock.svg", 12, UITokens.ok()), BadgeLabel.Tone.OK), UnlockPage.VAULT_UNLOCKED);
    }
}
