package io.xlogistx.nosneak.app.ui;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.BadgeLabel;
import io.xlogistx.gui.DirectoryField;
import io.xlogistx.gui.FormPanel;
import io.xlogistx.gui.IconUtil;
import io.xlogistx.gui.InlineMessage;
import io.xlogistx.gui.PanelBuilder;
import io.xlogistx.gui.ScrollablePanel;
import io.xlogistx.gui.SplashSidePanel;
import io.xlogistx.gui.StepperPanel;
import io.xlogistx.gui.UITokens;
import io.xlogistx.gui.WrapLabel;
import io.xlogistx.nosneak.app.NoSneakMain;
import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.app.ui.utility.AppPrefs;
import io.xlogistx.nosneak.app.ui.utility.Session;
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
 *       recoverable ({@link Form#VAULT_PASSWORD_WARNING}, 2026-10-29).
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
        public static final String VAULT_PASSWORD_WARNING = "Keep the vault password safe. IT IS NOT RECOVERABLE: "
                + "there is no reset, no recovery and nobody who can retrieve it. Lose it and the vault, the database "
                + "and everything they hold are gone for good.";

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

    // step-1 tooltips (2026-10-29): what each input is for, hovered on the field itself
    private static final String TIP_LOCATION = "The directory NoSneak keeps its vault and encrypted database in. "
            + "An empty folder creates a new store; a folder that already holds a vault opens it.";
    private static final String TIP_VAULT_PASSWORD = "Unlocks the vault that holds every other secret of this store. "
            + "It is never written anywhere and it cannot be recovered or reset: keep it safe.";
    private static final String TIP_OPERATOR = "The store's super-admin: the account you sign in with from now on.";
    private static final String TIP_OPERATOR_PASSWORD = "The operator's sign-in password; different from the vault password. "
            + "It can be changed later from Account \u2192 Profile.";
    private static final String TIP_OPERATOR_CONFIRM = "Type the operator password again.";
    private static final String TIP_DB_USER = "The H2 database account; leave the default unless you have a reason.";
    private static final String TIP_DB_PASSWORD = "The H2 database password. Empty = generated and kept only in the vault.";
    private static final String TIP_DB_ENCRYPTION = "The password that encrypts the H2 file on disk. Empty = generated and kept only in the vault.";

    private final StoreOpener opener;
    private final Consumer<ShiroDSDomainSecurityManager> onStoreOpened;
    private Session session;

    private final StepperPanel steps = new StepperPanel();
    private final int stepOpen;
    private final int stepSign;
    private boolean storeOpen;

    // step 1
    private final DirectoryField location = new DirectoryField();
    private final JPasswordField vaultPassword = new JPasswordField(20);
    private final InlineMessage storeMessage = new InlineMessage();
    private final FormPanel storeForm = new FormPanel();
    private final JTextField operatorID = PanelBuilder.textField("", 20);
    private final JPasswordField operatorPassword = new JPasswordField(20);
    private final JPasswordField operatorConfirm = new JPasswordField(20);
    private final JTextField dbUser = PanelBuilder.textField(NoSneakStore.DEFAULT_DB_USER, 20);
    private final JPasswordField dbPassword = new JPasswordField(20);
    private final JPasswordField dbEncryptionPassword = new JPasswordField(20);
    private final JButton openButton = UITokens.primary(new JButton("Open"));

    // step 2
    private final JTextField username = new JTextField(20);
    private final JPasswordField password = new JPasswordField(20);
    private final JPasswordField confirmPassword = new JPasswordField(20);
    private final FormPanel signForm = new FormPanel();
    private final InlineMessage signMessage = new InlineMessage();
    private final JButton signButton = UITokens.primary(new JButton("Sign in"));
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

        add(buildSplash(), "growy");
        add(buildRight(), "grow");

        stepOpen = steps.addStep("Open store", "The directory NoSneak keeps its vault and encrypted database in", buildOpenStep());
        stepSign = steps.addStep("Sign in", "Your account in this store", buildSignStep());
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
                "Scans run from this machine under its own address. Nothing hides, nothing floods, nothing breaks in.",
                "Reports, chats, captures and skills stay in a local encrypted store, opened with your own vault password and kept under your account.",
                "The assistant runs on a provider you configure with your own API key, and sees a report only when you attach it.");
        String footer = NoSneakMain.VERSION.getName() + " " + NoSneakMain.VERSION.version()
                + " · Java " + System.getProperty("java.version")
                + " · " + System.getProperty("os.name") + " " + System.getProperty("os.arch");
        return new SplashSidePanel(
                IconUtil.svgIcon("io/xlogistx/gui/icons/shield.svg", 26, new Color(0xA9A8F0)),
                "NoSneak",
                "What does your network expose, and how good is its posture?",
                MenuBarFactory.TAGLINE + ". TLS and certificate trust, running services, live hosts with their MAC and vendor. "
                        + "It looks and reports; it never breaks in.",
                points, footer);
    }

    private JComponent buildRight() {
        Color ground = new Color(0xF4F4F7);

        JPanel card = new JPanel(new MigLayout("insets 32 36 28 36, fillx, wrap 1, gapy 0", "[grow,fill]"));
        card.setBackground(UITokens.surface());
        card.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        card.add(steps, "growx");

        WrapLabel text = new WrapLabel("First time here? Pick an empty folder in step 1 and NoSneak creates the vault, the encrypted database "
                + "and your operator account in one go. Installations made before October 2026 cannot be opened and say why.");
        text.setFont(UITokens.font(Font.PLAIN, -1f));
        card.add(callout(new IconUtil.InfoIcon(16), text, ground), "growx, gaptop 16");

        // the card sits centred in the free space and scrolls only when the window is shorter than it
        ScrollablePanel centre = new ScrollablePanel(new MigLayout("insets 40 24 40 24, fill", "[grow,center]", "[grow,center]"));
        centre.setBackground(ground);
        centre.add(card, "wmin 420, wmax 560, growx");

        JScrollPane scroll = new JScrollPane(centre, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(ground);
        return scroll;
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
        location.dialogTitle("Choose the no-sneak directory")
                .placeholder("No directory chosen")
                .startDirectory(() -> {
                    File last = AppPrefs.storeLocation();
                    return last != null ? last : new File(System.getProperty("user.home"));
                });
        location.onChange(_ -> applyStoreMode(path()));

        location.setToolTipText(TIP_LOCATION);
        location.getPathField().setToolTipText(TIP_LOCATION);
        location.getChooseButton().setToolTipText("Choose the directory");
        vaultPassword.setToolTipText(TIP_VAULT_PASSWORD);
        operatorID.setToolTipText(TIP_OPERATOR);
        operatorPassword.setToolTipText(TIP_OPERATOR_PASSWORD);
        operatorConfirm.setToolTipText(TIP_OPERATOR_CONFIRM);
        dbUser.setToolTipText(TIP_DB_USER);
        dbPassword.setToolTipText(TIP_DB_PASSWORD);
        dbEncryptionPassword.setToolTipText(TIP_DB_ENCRYPTION);

        storeForm.field("Location", location);
        storeForm.row(storeMessage, "growx, gaptop 4");
        storeForm.requiredField("Vault password", PanelBuilder.passwordField(vaultPassword),
                "The one secret every later run needs. It is never written anywhere.");
        // the warning stands out from the muted hints: bold, in the warning colour, on its own tinted row
        WrapLabel warning = new WrapLabel(Form.VAULT_PASSWORD_WARNING);
        warning.setFont(UITokens.font(Font.BOLD, -1f));
        warning.setForeground(UITokens.warn());
        storeForm.row(callout(IconUtil.svgIcon("io/xlogistx/gui/icons/alert.svg", 16, UITokens.warn()), warning, UITokens.warnSoft()),
                "growx, gaptop 6");
        storeForm.group(FIRST_RUN, () -> {
            storeForm.requiredField("Operator username", operatorID, "The store's super-admin: the account you sign in with from now on.");
            storeForm.requiredField("Operator password", PanelBuilder.passwordField(operatorPassword));
            storeForm.requiredField("Confirm operator password", PanelBuilder.passwordField(operatorConfirm));
            storeForm.field("Database username", dbUser);
            storeForm.field("Database password", PanelBuilder.passwordField(dbPassword), "Empty = generated and kept only in the vault.");
            storeForm.field("Database encryption password", PanelBuilder.passwordField(dbEncryptionPassword), "Empty = generated and kept only in the vault.");
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
        signForm.field("Username", username);
        signForm.field("Password", PanelBuilder.passwordField(password));
        signForm.group(REGISTER, () -> signForm.field("Confirm password", PanelBuilder.passwordField(confirmPassword)));
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
        openButton.setText(create ? "Create" : "Open");
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

        BackgroundTask.run(this, openButton, () -> {
            try {
                ShiroDSDomainSecurityManager dsm = opener.open(path, vault, firstRun);
                AppPrefs.storeLocation(path);
                return (Object) dsm;
            } catch (Exception e) {
                return e;
            } finally {
                Arrays.fill(vault, '\0');
                Arrays.fill(opPwd, '\0');
            }
        }, result -> {
            if (result instanceof Exception e) {
                storeMessage.error(reason(e));
                vaultPassword.requestFocusInWindow();
                return;
            }
            clearStoreSecrets();
            ShiroDSDomainSecurityManager dsm = (ShiroDSDomainSecurityManager) result;
            onStoreOpened.accept(dsm);
            markStoreOpened(path);
        });
    }

    private static String reason(Exception e) {
        String m = e.getMessage();
        return m != null && !m.isBlank() ? m : e.getClass().getSimpleName();
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
        steps.complete(stepOpen, (path != null ? path : "") + " · vault unlocked", null);
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
        signButton.setText(registering ? "Register" : "Sign in");
        modeToggle.setText(registering ? "Already have an account? Sign in" : "Create another account in this store");
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
        return new BadgeLabel("vault unlocked", IconUtil.svgIcon("io/xlogistx/gui/icons/lock.svg", 12, UITokens.ok()), BadgeLabel.Tone.OK);
    }
}
