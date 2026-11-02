package io.xlogistx.nosneak.app;

import org.zoxweb.shared.util.*;

/**
 * The application's UI descriptors (maintainer's rule, 2026-11-01): every GUI component or panel
 * the app builds has a constant in one of the enums here, implementing zoxweb's {@link GetName}
 * (the AWT component name, dotted and stable — what a test or a script finds it by),
 * {@link GetDisplayName} (the text it shows: a button's or label's text, a field's placeholder, a
 * column header) and {@link GetDescription} (its tooltip). The panels render through those three
 * methods and carry no literal strings of their own; gui-audio's
 * {@code GUIUtil.applyProp(component, ref)} is the one place that maps them onto a component.
 * The twin of core's {@code NSCoreUtil}.
 */
public class NSAppUtil {
    private NSAppUtil() {
    }

    /**
     * The Probe groups page (2026-11-01): the card behind the Probe library's Groups button, its bar, how-to and detail pane.
     */
    public enum ProbeGroupsPage implements GetNameDescriptionDisplay {
        PAGE("probeGroups", "Probe groups", "Named sets of probes to run in one go when setting up a scan"),
        OPEN("probeGroups.open", "Probe groups manager", "Manage probes grouping"),
        TITLE("probeGroups.title", "Probe groups manager", null),
        SUBTITLE("probeGroups.subtitle", "In this section you can create probe groups. A probe group is a set of reusable probes that you can assign to a scan instead of adding them individually.", null),
        BACK("probeGroups.back", "Probe library", "Back to the probe library"),
        NEW_GROUP("probeGroups.new", "New group", "Name a group and select its probes in a checklist"),
        SEARCH("probeGroups.search", "Search name, description, probe", "Filters the groups by name, description or any member probe"),
        COUNT("probeGroups.count", "", "How many groups are listed"),
        TABLE("probeGroups.table", "Groups", "Your probe groups; select one to read it, double-click to edit it"),
        HOWTO_TITLE("probeGroups.howto", "What a group is", null),
        HOWTO_TEXT("probeGroups.howto.text", "A group is a named list of probes — bundled ones and yours — that you select in one go "
                + "under Add probe on the Scan page. It stores the probes' names, so it keeps working when a probe "
                + "is renamed or re-saved, and it says which members no longer exist. The scan runs the probes; "
                + "the report records them, never the group. Two ways to make one:", null),
        HOWTO_NEW("probeGroups.howto.new", "New group", "Name it, tick its probes in the checklist, Save."),
        HOWTO_FROM_SCAN("probeGroups.howto.fromScan", "Save selected as group on the Scan page", "Select the probes you want, then Add probe › Save selected as group…"),
        GROUP_TITLE("probeGroups.group.title", "", "The selected group"),
        EDIT("probeGroups.group.edit", "Edit", "Change the group's name, description or probes"),
        DELETE("probeGroups.group.delete", "Delete", "Delete the group; its probes stay"),
        DELETE_DIALOG("probeGroups.group.delete.dialog", "Delete group", null),
        FACT_DESCRIPTION("probeGroups.group.description", "Description", null),
        FACT_PROBES("probeGroups.group.probes", "Probes", "How many members resolve to a probe now, and how many do not"),
        FACT_MISSING("probeGroups.group.missing", "Missing", "Members that match no probe any more"),
        FACT_SOURCE("probeGroups.group.source", "Source", null),
        SOURCE_MINE("probeGroups.group.source.mine", "mine, stored under your account", null),
        SOURCE_PRESET("probeGroups.group.source.preset", "bundled with no-sneak", null),
        MEMBERS("probeGroups.group.members", "Probes", "The members: bundled, yours, or missing"),
        MEMBER_LIST("probeGroups.group.members.list", "", "One line per member probe"),
        BADGE_BUNDLED("probeGroups.badge.bundled", "bundled", "A probe that ships with no-sneak"),
        BADGE_MINE("probeGroups.badge.mine", "mine", "A probe stored under your account"),
        BADGE_MISSING("probeGroups.badge.missing", "missing", "No probe of this name exists any more; dropped when the group is saved again");

        private final GetNameDescriptionDisplay gndd;

        ProbeGroupsPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /**
     * The group editor (2026-11-01): name, description, a searchable checklist of every probe, Save and Cancel.
     */
    public enum ProbeGroupEditor implements GetNameDescriptionDisplay {
        EDITOR("probeGroupEditor", "Group editor", "Name a group and select its probes"),
        BACK("probeGroupEditor.back", "", "Back to the groups"),
        TITLE_NEW("probeGroupEditor.title.new", "New group", null),
        TITLE_EDIT("probeGroupEditor.title.edit", "Edit group", null),
        NAME("probeGroupEditor.name", "Name", "The group's name; a group of yours with the same name is updated"),
        NAME_FIELD("probeGroupEditor.name.field", "web-tier, mail, everything-tls…", "The group's name; a group of yours with the same name is updated"),
        DESCRIPTION("probeGroupEditor.description", "Description", "One line, optional"),
        DESCRIPTION_FIELD("probeGroupEditor.description.field", "optional, one line", "One line, optional"),
        SEARCH("probeGroupEditor.search", "Search probes", "Narrows the checklist to probes whose name contains the text"),
        COUNT("probeGroupEditor.count", "", "How many probes are selected"),
        CHECK("probeGroupEditor.check", "", "Not in the library any more, dropped on save"),
        LIST("probeGroupEditor.list", "", "Every probe a scan can run; select the members"),
        SECTION_BUNDLED("probeGroupEditor.bundled", "Bundled probes", "The probes that ship with the app"),
        SECTION_MINE("probeGroupEditor.mine", "My probes", "The probes stored under your account"),
        EMPTY_BUNDLED("probeGroupEditor.bundled.empty", "None loaded", null),
        EMPTY_MINE("probeGroupEditor.mine.empty", "No probes yet", null),
        ALL("probeGroupEditor.all", "All", "Tick or untick every probe of this section"),
        SAVE("probeGroupEditor.save", "Save", "Store the group and go back to the list"),
        CANCEL("probeGroupEditor.cancel", "Cancel", "Discard the changes");

        private final GetNameDescriptionDisplay gndd;

        ProbeGroupEditor(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /**
     * The GROUPS section of the Scan page's Add probe popup, and its Save selected as group dialog (2026-11-01).
     */
    public enum ProbeGroupMenu implements GetNameDescriptionDisplay {
        HEADER("probeMenu.groups", "GROUPS", "Saved groups: a tick adds the group's probes, an untick removes them"),
        EMPTY("probeMenu.groups.empty", "No groups yet — save selected probes as a group", null),
        SAVE_AS("probeMenu.groups.saveAs", "Save selected as group…", "Keep the selected probes as a named group to tick again in one go"),
        SAVE_AS_DIALOG("probeMenu.groups.saveAs.dialog", "Save ticked probes as a group", null),
        SAVE_AS_NAME("probeMenu.groups.saveAs.name", "Name", "The group's name; a group of yours with the same name is updated"),
        SAVE_AS_NAME_FIELD("probeMenu.groups.saveAs.name.field", "web-tier, mail, everything-tls…", "The group's name; a group of yours with the same name is updated"),
        SAVE_AS_DESCRIPTION("probeMenu.groups.saveAs.description", "Description", "One line, optional"),
        SAVE_AS_DESCRIPTION_FIELD("probeMenu.groups.saveAs.description.field", "optional, one line", "One line, optional"),
        SAVE_AS_PROBES("probeMenu.groups.saveAs.probes", "Probes", "The ticked probes, in catalog order, as the group will store them");

        private final GetNameDescriptionDisplay gndd;

        ProbeGroupMenu(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /**
     * The columns of the Probe groups table, in order; {@code ProbeGroupModel} reads its headers here.
     */
    public enum ProbeGroupColumn implements GetNameDescriptionDisplay {
        NAME("probeGroups.col.name", "Name", "The group's name"),
        PROBES("probeGroups.col.probes", "Probes", "How many members resolve to a probe now, and how many are missing"),
        DESCRIPTION("probeGroups.col.description", "Description", "The group's one-line description");

        private final GetNameDescriptionDisplay gndd;

        ProbeGroupColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** Every page the sidebar offers, in sidebar order (moved here from {@code Navigator.Screen}, 2026-11-01): the display name is what the sidebar, the View menu and the page title show, the description their tooltip. */
    public enum Screen implements GetNameDescriptionDisplay {
        SCAN("nav.scan", "Scan", "Targets, ports and options; the hosts, services and raw report of the run"),
        SCAN_HISTORY("nav.scanHistory", "Scan History", "Every report you ran, kept under your account"),
        PROBES("nav.probes", "Probe Library", "The bundled service probes and yours, readable in full"),
        CHAT("nav.chat", "Chat", "Your chats with the assistant: open one, or start a new one"),
        CAPTURE("nav.capture", "Capture", "Screen areas shot at once, kept for the chat"),
        SKILLS("nav.skills", "Skills", "Instructions the assistant carries into a chat"),
        PROVIDERS("nav.providers", "Providers", "Which of your API keys the assistant may use, and their models"),
        PROFILE("nav.profile", "Profile", "Your name, identifiers and addresses"),
        API_KEYS("nav.apiKeys", "API Keys", "Your password and the third-party keys the assistant borrows"),
        SETTINGS("nav.settings", "Settings", "The MAC vendor list, the assistant's reply timeout, and the store's backup and restore"),
        ACL("nav.acl", "Access Control", "Subjects, permissions, roles and grants (super-admin only)");

        private final GetNameDescriptionDisplay gndd;

        Screen(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }

        /** The screen whose component name is {@code key}: how the sidebar's selection finds its page. */
        public static Screen byName(String key) {
            for (Screen s : values()) if (s.getName().equals(key)) return s;
            throw new IllegalArgumentException("no screen named " + key);
        }
    }

    /** The scan result's three tabs (2026-10-27, moved here from {@code ScanResultView.Tab}): the display name is the tab's title, the description its tooltip. */
    public enum ScanResultTab implements GetNameDescriptionDisplay {
        HOSTS("scanResult.tab.hosts", "Hosts", "Every host of the run: address, MAC and vendor, status, open ports, services, TLS and PQC readiness; select one for its detail"),
        SERVICES("scanResult.tab.services", "Services", "Every open port of the run, flat: host, port, service, version and what it said"),
        RAW("scanResult.tab.raw", "Raw JSON", "The report exactly as the engine wrote it");

        private final GetNameDescriptionDisplay gndd;

        ScanResultTab(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Access Control page's five views (2026-10-27, moved here from {@code SubjectSecManagerPanel.View}): the display name is the tab's title, the description its tooltip and the view's subtitle. */
    public enum AclView implements GetNameDescriptionDisplay {
        SUBJECTS("acl.view.subjects", "Subjects", "Security subjects and their principals, credentials and grants"),
        PERMISSIONS("acl.view.permissions", "Permissions", "Permission definitions, scoped by application"),
        ROLES("acl.view.roles", "Roles", "Named bundles of permissions"),
        ROLE_GROUPS("acl.view.roleGroups", "Role groups", "Bundles of roles granted together"),
        GRANTS("acl.view.grants", "Grants", "Permission, role and role-group grants bound to subjects");

        private final GetNameDescriptionDisplay gndd;

        AclView(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Probe library's All / Bundled / Mine segment (2026-10-27, moved here from {@code ProbeLibraryModel.Filter}): the display name is the segment's text, the description its tooltip. */
    public enum ProbeLibraryFilter implements GetNameDescriptionDisplay {
        ALL("probeLibrary.filter.all", "All", "Every probe: the bundled ones and yours"),
        BUNDLED("probeLibrary.filter.bundled", "Bundled", "The probes that ship with the app, read-only"),
        MINE("probeLibrary.filter.mine", "Mine", "The probes stored under your account");

        private final GetNameDescriptionDisplay gndd;

        ProbeLibraryFilter(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The columns of the Probe library table, in order; {@code ProbeLibraryModel} reads its headers here and its {@code COL_*} are the ordinals. */
    public enum ProbeLibraryColumn implements GetNameDescriptionDisplay {
        NAME("probeLibrary.col.name", "Name", "The probe's name"),
        SERVICE("probeLibrary.col.service", "Service", "The service the probe identifies"),
        PORTS("probeLibrary.col.ports", "Ports", "The ports the probe declares"),
        TRANSPORT("probeLibrary.col.transport", "Transport", "tcp or udp"),
        PRIORITY("probeLibrary.col.priority", "Priority", "Higher runs first on an open port"),
        SOURCE("probeLibrary.col.source", "Source", "bundled with the app, or mine");

        private final GetNameDescriptionDisplay gndd;

        ProbeLibraryColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /**
     * The unlock screen (2026-10-24, descriptors 2026-11-01): the splash on the left, step 1 (Open store: the
     * directory, the vault password, the first-run rows) and its texts. Step 2 is {@link SignInForm}.
     * A {@code *_FIELD} constant names an input and carries its tooltip; the constant without the suffix is
     * the form label beside it.
     */
    public enum UnlockPage implements GetNameDescriptionDisplay {
        PAGE("unlock", "", "The screen shown until a subject is signed in: open the store, then sign in"),
        SPLASH_BRAND("unlock.splash.brand", "NoSneak", null),
        SPLASH_TITLE("unlock.splash.title", "What does your network expose, and how good is its posture?", null),
        SPLASH_TAGLINE("unlock.splash.tagline", "TLS and certificate trust, running services, live hosts with their MAC and vendor. It looks and reports; it never breaks in.", null),
        SPLASH_POINT_SCANS("unlock.splash.point.scans", "Scans run from this machine under its own address. Nothing hides, nothing floods, nothing breaks in.", null),
        SPLASH_POINT_STORE("unlock.splash.point.store", "Reports, chats, captures and skills stay in a local encrypted store, opened with your own vault password and kept under your account.", null),
        SPLASH_POINT_ASSISTANT("unlock.splash.point.assistant", "The assistant runs on a provider you configure with your own API key, and sees a report only when you attach it.", null),
        FIRST_RUN_NOTE("unlock.firstRunNote", "First time here? Pick an empty folder in step 1 and NoSneak creates the vault, the encrypted database "
                + "and your operator account in one go. Installations made before October 2026 cannot be opened and say why.", null),
        STEP_OPEN("unlock.step.open", "Open store", "The directory NoSneak keeps its vault and encrypted database in"),
        STEP_SIGN_IN("unlock.step.signIn", "Sign in", "Your account in this store"),
        STORE_FORM("unlock.storeForm", "", "Step 1: where the store is and how to unlock it"),
        LOCATION("unlock.location", "Location", null),
        LOCATION_FIELD("unlock.location.field", "", "The directory NoSneak keeps its vault and encrypted database in. "
                + "An empty folder creates a new store; a folder that already holds a vault opens it."),
        LOCATION_PLACEHOLDER("unlock.location.placeholder", "No directory chosen", null),
        LOCATION_DIALOG("unlock.location.dialog", "Choose the no-sneak directory", null),
        LOCATION_CHOOSE("unlock.location.choose", "", "Choose the directory"),
        VAULT_PASSWORD("unlock.vaultPassword", "Vault password", null),
        VAULT_PASSWORD_FIELD("unlock.vaultPassword.field", "", "Unlocks the vault that holds every other secret of this store. "
                + "It is never written anywhere and it cannot be recovered or reset: keep it safe."),
        VAULT_PASSWORD_HINT("unlock.vaultPassword.hint", "The one secret every later run needs. It is never written anywhere.", null),
        VAULT_PASSWORD_WARNING("unlock.vaultPassword.warning", "Keep the vault password safe. IT IS NOT RECOVERABLE: "
                + "there is no reset, no recovery and nobody who can retrieve it. Lose it and the vault, the database "
                + "and everything they hold are gone for good.", null),
        OPERATOR("unlock.operator", "Operator username", null),
        OPERATOR_FIELD("unlock.operator.field", "", "The store's super-admin: the account you sign in with from now on."),
        OPERATOR_PASSWORD("unlock.operatorPassword", "Operator password", null),
        OPERATOR_PASSWORD_FIELD("unlock.operatorPassword.field", "", "The operator's sign-in password; different from the vault password. "
                + "It can be changed later from Account → Profile."),
        OPERATOR_CONFIRM("unlock.operatorConfirm", "Confirm operator password", null),
        OPERATOR_CONFIRM_FIELD("unlock.operatorConfirm.field", "", "Type the operator password again."),
        DB_USER("unlock.dbUser", "Database username", null),
        DB_USER_FIELD("unlock.dbUser.field", "", "The H2 database account; leave the default unless you have a reason."),
        DB_PASSWORD("unlock.dbPassword", "Database password", null),
        DB_PASSWORD_FIELD("unlock.dbPassword.field", "", "The H2 database password. Empty = generated and kept only in the vault."),
        DB_ENCRYPTION("unlock.dbEncryption", "Database encryption password", null),
        DB_ENCRYPTION_FIELD("unlock.dbEncryption.field", "", "The password that encrypts the H2 file on disk. Empty = generated and kept only in the vault."),
        DB_GENERATED_HINT("unlock.db.generatedHint", "Empty = generated and kept only in the vault.", null),
        OPEN("unlock.open", "Open", "Open the vault in the chosen directory"),
        CREATE("unlock.create", "Create", "Create the vault, the database and the operator account in the chosen directory"),
        VAULT_UNLOCKED("unlock.vaultUnlocked", "vault unlocked", "The store is open for the life of the process");

        private final GetNameDescriptionDisplay gndd;

        UnlockPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** Step 2 of the unlock screen: username and password, the register mode and the link that flips it (2026-11-01). */
    public enum SignInForm implements GetNameDescriptionDisplay {
        FORM("signIn", "", "Step 2: your account in this store"),
        USERNAME("signIn.username", "Username", null),
        USERNAME_FIELD("signIn.username.field", "", null),
        PASSWORD("signIn.password", "Password", null),
        PASSWORD_FIELD("signIn.password.field", "", null),
        CONFIRM("signIn.confirm", "Confirm password", null),
        CONFIRM_FIELD("signIn.confirm.field", "", null),
        SIGN_IN("signIn.signIn", "Sign in", null),
        REGISTER("signIn.register", "Register", null),
        TO_REGISTER("signIn.toRegister", "Create another account in this store", null),
        TO_SIGN_IN("signIn.toSignIn", "Already have an account? Sign in", null);

        private final GetNameDescriptionDisplay gndd;

        SignInForm(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The application frame ({@code NoSneakMain.AppFrame}): its title. */
    public enum MainWindow implements GetNameDescriptionDisplay {
        WINDOW("app.window", "NoSneak", null);

        private final GetNameDescriptionDisplay gndd;

        MainWindow(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The PQC registry placeholder screen ({@code PQCRegistryPanel}): two toggles over an empty card, honestly unbuilt. */
    public enum PQCRegistryPage implements GetNameDescriptionDisplay {
        PAGE("pqcRegistry", "", "A placeholder: no specification was ever settled for this screen"),
        PLACEHOLDER_LEFT("pqcRegistry.placeholder.left", "PLACEHOLDER", null),
        PLACEHOLDER_RIGHT("pqcRegistry.placeholder.right", "PLACEHOLDER", null);

        private final GetNameDescriptionDisplay gndd;

        PQCRegistryPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The scan set-up form ({@code ScanFormPanel}, 2026-11-01): its labels, fields, check boxes, flag hints, buttons. */
    public enum ScanForm implements GetNameDescriptionDisplay {
        PANEL("scanForm", "", null),
        TARGETS("scanForm.targets", "Targets", null),
        TARGETS_FIELD("scanForm.targets.field", "10.0.0.0/24  host.example.com  10.0.0.5-9", null),
        TARGETS_HINT("scanForm.targets.hint", "Hosts, ranges or CIDR blocks you own or are authorised to assess.", null),
        PORTS("scanForm.ports", "Ports", null),
        PORTS_FIELD("scanForm.ports.field", "1-1024 (default when empty)", "Type a -p spec to scan other ports."),
        PORTS_EMPTY("scanForm.ports.empty", "Empty", null),
        NAME("scanForm.name", "Name (optional)", null),
        NAME_FIELD("scanForm.name.field", "e.g. Office segment, weekly", null),
        OPTIONS("scanForm.options", "Options", null),
        SERVICE_DETECTION("scanForm.serviceDetection", "Service detection", null),
        SERVICE_DETECTION_FLAG("scanForm.serviceDetection.flag", "-sV", null),
        DISCOVERY_ONLY("scanForm.discoveryOnly", "Host discovery only", null),
        DISCOVERY_ONLY_FLAG("scanForm.discoveryOnly.flag", "-sn", null),
        SKIP_PING("scanForm.skipPing", "Skip ping", null),
        SKIP_PING_FLAG("scanForm.skipPing.flag", "-Pn", null),
        UP_ONLY("scanForm.upOnly", "Live hosts only", null),
        UP_ONLY_FLAG("scanForm.upOnly.flag", "--up-only", null),
        OPEN_ONLY("scanForm.openOnly", "Open ports only", null),
        OPEN_ONLY_FLAG("scanForm.openOnly.flag", "--open", null),
        TIMING("scanForm.timing", "Timing", null),
        TIMING_CONTROL("scanForm.timing.control", "", null),
        MAX_IN_FLIGHT("scanForm.maxInFlight", "Max in flight", null),
        MAX_IN_FLIGHT_FIELD("scanForm.maxInFlight.field", "", null),
        MIN_RTT("scanForm.minRtt", "Min RTT timeout (ms)", null),
        MIN_RTT_FIELD("scanForm.minRtt.field", "", null),
        PROBES("scanForm.probes", "Probes", null),
        PROBE_SLOT("scanForm.probes.slot", "", null),
        MATCH("scanForm.match", "Match", null),
        MATCH_CONTROL("scanForm.match.control", "", null),
        COMMAND("scanForm.command", "Command", null),
        COMMAND_HINT("scanForm.command.hint", "generated from the form · edit it and the form follows", null),
        COMMAND_FIELD("scanForm.command.field", "", null),
        COPY("scanForm.copy", "Copy", null),
        HELP("scanForm.help", "", "Command-line reference"),
        RUN("scanForm.run", "Run scan", null),
        STOP("scanForm.stop", "Stop", "Stop the running scan; what completed so far is shown, nothing is saved"),
        MESSAGE("scanForm.message", "", null);

        private final GetNameDescriptionDisplay gndd;

        ScanForm(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The scan result ({@code ScanResultView}, 2026-11-01): header, state badge, buttons, tabs' contents; the tabs are {@link ScanResultTab}. */
    public enum ScanResult implements GetNameDescriptionDisplay {
        VIEW("scanResult", "", null),
        EMPTY("scanResult.empty", "Run a scan to see its hosts, services and raw report here.", null),
        TITLE("scanResult.title", "", null),
        TITLE_DEFAULT("scanResult.title.default", "Result", null),
        META("scanResult.meta", "", null),
        STATE("scanResult.state", "", null),
        STATE_STOPPED("scanResult.state.stopped", "stopped · not saved", null),
        STATE_SAVED("scanResult.state.saved", "saved to history", null),
        STATE_NOT_SAVED("scanResult.state.notSaved", "not saved", null),
        COUNTS("scanResult.counts", "", null),
        COPY("scanResult.copy", "", "Copy the raw report to the clipboard"),
        SEND("scanResult.send", "Send to assistant", null),
        RERUN("scanResult.rerun", "Scan again", "Load this scan's command, probes and name into New scan"),
        TABS("scanResult.tabs", "", null),
        HOSTS_TABLE("scanResult.hosts.table", "", null),
        SERVICES_TABLE("scanResult.services.table", "", null),
        RAW_TEXT("scanResult.raw.text", "", null);

        private final GetNameDescriptionDisplay gndd;

        ScanResult(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The columns of the result's Hosts table, in order; the model's {@code COL_*} are the ordinals. */
    public enum ScanResultHostColumn implements GetNameDescriptionDisplay {
        HOST("scanResult.hosts.col.host", "Host", null),
        MAC("scanResult.hosts.col.mac", "MAC", null),
        VENDOR("scanResult.hosts.col.vendor", "Vendor", null),
        STATUS("scanResult.hosts.col.status", "Status", null),
        OPEN("scanResult.hosts.col.open", "Open", null),
        SERVICES("scanResult.hosts.col.services", "Services", null),
        TLS("scanResult.hosts.col.tls", "TLS", null),
        POSTURE("scanResult.hosts.col.posture", "PQC readiness", null);

        private final GetNameDescriptionDisplay gndd;

        ScanResultHostColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The columns of the result's Services table, in order. */
    public enum ScanResultServiceColumn implements GetNameDescriptionDisplay {
        HOST("scanResult.services.col.host", "Host", null),
        PORT("scanResult.services.col.port", "Port", null),
        SERVICE("scanResult.services.col.service", "Service", null),
        VERSION("scanResult.services.col.version", "Version · probe", null),
        TLS("scanResult.services.col.tls", "TLS", null);

        private final GetNameDescriptionDisplay gndd;

        ScanResultServiceColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The host detail pane of the result's Hosts tab (2026-11-01): its sections, key-value keys and the ports table's columns. */
    public enum HostDetail implements GetNameDescriptionDisplay {
        PANE("hostDetail", "", null),
        ADDRESS("hostDetail.address", "", null),
        SUBTITLE("hostDetail.subtitle", "", null),
        ADAPTER("hostDetail.adapter", "Network adapter", null),
        ADAPTER_MAC("hostDetail.adapter.mac", "MAC", null),
        ADAPTER_VENDOR("hostDetail.adapter.vendor", "Vendor", null),
        PORTS("hostDetail.ports", "Ports", null),
        PORTS_TABLE("hostDetail.ports.table", "", null),
        PORT_COL_PORT("hostDetail.ports.col.port", "Port", null),
        PORT_COL_SERVICE("hostDetail.ports.col.service", "Service", null),
        PORT_COL_VERSION("hostDetail.ports.col.version", "Version · probe", null),
        IDENTIFICATIONS("hostDetail.identifications", "Identifications", null),
        TLS("hostDetail.tls", "TLS posture", null),
        TLS_PROTOCOL("hostDetail.tls.protocol", "Protocol", null),
        TLS_KEY_EXCHANGE("hostDetail.tls.keyExchange", "Key exchange", null),
        TLS_CIPHER("hostDetail.tls.cipher", "Cipher", null),
        TLS_CERTIFICATE("hostDetail.tls.certificate", "Certificate", null),
        TLS_CHAIN("hostDetail.tls.chain", "Chain", null),
        TLS_GROUPS("hostDetail.tls.groups", "Groups offered", null),
        TLS_VERSIONS("hostDetail.tls.versions", "Versions", null),
        TLS_NONE("hostDetail.tls.none", "No TLS endpoint answered on this host, so there is no posture to grade.", null),
        VERDICT("hostDetail.verdict", "", null),
        VERDICT_BADGE("hostDetail.verdict.badge", "", null),
        VERDICT_TEXT("hostDetail.verdict.text", "", null);

        private final GetNameDescriptionDisplay gndd;

        HostDetail(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The signed-in window's shell (2026-11-01): the header bar, the Sign out action, the sidebar's sections and footer. */
    public enum Shell implements GetNameDescriptionDisplay {
        PANEL("shell", "", "The signed-in application: header, sidebar, one card per page, status bar"),
        BRAND("shell.brand", "NoSneak", null),
        STORE_CHIP("shell.store", "vault open", "Settings > Backup saves a copy."),
        STORE_UNKNOWN("shell.store.unknown", "store", null),
        SIGN_OUT("shell.signOut", "Sign out", "Sign out of NoSneak and return to the unlock screen"),
        SIGN_OUT_DIALOG("shell.signOut.dialog", "Sign out", null),
        SECTION_SCAN("shell.section.scan", "Scan", null),
        SECTION_ASSISTANT("shell.section.assistant", "Assistant", null),
        SECTION_ACCOUNT("shell.section.account", "Account", null),
        SECTION_ADMIN("shell.section.admin", "Admin", null),
        HELP("shell.help", "Help", "Every page, and what the tool will not do"),
        VERSION("shell.version", "", "version, Java, platform, store");

        private final GetNameDescriptionDisplay gndd;

        Shell(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The status bar under the pages (2026-10-27): who is signed in on the left, the MAC vendor list's state on the right. */
    public enum StatusBar implements GetNameDescriptionDisplay {
        BAR("statusBar", "", null),
        SESSION("statusBar.session", "Signed out", null),
        SIGNED_IN("statusBar.session.signedIn", "Signed in as", null),
        VENDORS("statusBar.vendors", "", "The Wireshark manufacturer list that names each host's vendor in scan reports. Settings > Sync refreshes it."),
        VENDORS_LOADING("statusBar.vendors.loading", "MAC vendors: loading…", null),
        VENDORS_PREFIX("statusBar.vendors.prefix", "MAC vendors:", null);

        private final GetNameDescriptionDisplay gndd;

        StatusBar(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The menu bar of the signed-in window (File / View / Help), its dialogs and the About card (2026-11-01). */
    public enum MenuBar implements GetNameDescriptionDisplay {
        BAR("menu", "", null),
        FILE("menu.file", "File", null),
        VIEW("menu.view", "View", null),
        HELP("menu.help", "Help", null),
        SIGN_OUT("menu.file.signOut", "Sign out", "Sign out of NoSneak and return to the unlock screen"),
        SIGN_OUT_DIALOG("menu.file.signOut.dialog", "Sign out", null),
        VIEW_CHAT("menu.view.chat", "Assistant chat", null),
        ABOUT("menu.help.about", "About", "Name, version, Java, platform and the open vault"),
        HELP_ITEM("menu.help.help", "Help", "Every page, and what the tool will not do"),
        ABOUT_DIALOG("menu.about.dialog", "About", null),
        HELP_DIALOG("menu.help.dialog", "Help", null),
        ABOUT_CARD("menu.about", "", null),
        ABOUT_NAME("menu.about.name", "", null),
        ABOUT_TAGLINE("menu.about.tagline", "", null),
        ABOUT_SUMMARY("menu.about.summary", "", null),
        ABOUT_FACTS("menu.about.facts", "", null),
        FACT_VERSION("menu.about.version", "Version", null),
        FACT_JAVA("menu.about.java", "Java", null),
        FACT_PLATFORM("menu.about.platform", "Platform", null),
        FACT_VAULT("menu.about.vault", "Vault", null),
        VAULT_NOT_OPEN("menu.about.vault.notOpen", "(not open)", null),
        FACT_STORE("menu.about.store", "Store", null),
        ABOUT_TIPS("menu.about.tips", "Rest the pointer on any page, button, option or tab for a line on what it does.", null),
        ABOUT_HELP_LINK("menu.about.helpLink", "Help: every page, and what the tool will not do", "Open the page-by-page description");

        private final GetNameDescriptionDisplay gndd;

        MenuBar(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Access Control page (super-admin only): the tab host, and per view a search bar, a subtitle and a placeholder table; the views themselves are {@link AclView}. */
    public enum AclPage implements GetNameDescriptionDisplay {
        PAGE("acl", "", "Every subject in this store, with its permissions, roles, role groups and grants. Super-admin only."),
        TABS("acl.tabs", "", null),
        SUBJECTS_SEARCH_FIELD("acl.subjects.search.field", "", null),
        SUBJECTS_SEARCH("acl.subjects.search", "", "Search"),
        SUBJECTS_SUBTITLE("acl.subjects.subtitle", "", null),
        SUBJECTS_TABLE("acl.subjects.table", "", null),
        SUBJECTS_COL_NAME("acl.subjects.col.name", "Name", null),
        SUBJECTS_COL_PRINCIPAL("acl.subjects.col.principal", "Primary principal", null),
        SUBJECTS_COL_OWNS("acl.subjects.col.owns", "Owns", null),
        SUBJECTS_COL_ACTIONS("acl.subjects.col.actions", "", null),
        PERMISSIONS_SEARCH_FIELD("acl.permissions.search.field", "", null),
        PERMISSIONS_SEARCH("acl.permissions.search", "", "Search"),
        PERMISSIONS_SUBTITLE("acl.permissions.subtitle", "", null),
        PERMISSIONS_TABLE("acl.permissions.table", "", null),
        PERMISSIONS_COL_PERMISSION("acl.permissions.col.permission", "Permission", null),
        PERMISSIONS_COL_DESCRIPTION("acl.permissions.col.description", "Description", null),
        PERMISSIONS_COL_ACTIONS("acl.permissions.col.actions", "", null),
        ROLES_SEARCH_FIELD("acl.roles.search.field", "", null),
        ROLES_SEARCH("acl.roles.search", "", "Search"),
        ROLES_SUBTITLE("acl.roles.subtitle", "", null),
        ROLES_TABLE("acl.roles.table", "", null),
        ROLES_COL_ROLE("acl.roles.col.role", "Role", null),
        ROLES_COL_DESCRIPTION("acl.roles.col.description", "Description", null),
        ROLES_COL_ACTIONS("acl.roles.col.actions", "", null),
        ROLE_GROUPS_SEARCH_FIELD("acl.roleGroups.search.field", "", null),
        ROLE_GROUPS_SEARCH("acl.roleGroups.search", "", "Search"),
        ROLE_GROUPS_SUBTITLE("acl.roleGroups.subtitle", "", null),
        ROLE_GROUPS_TABLE("acl.roleGroups.table", "", null),
        ROLE_GROUPS_COL_GROUP("acl.roleGroups.col.group", "Role Group", null),
        ROLE_GROUPS_COL_ROLES("acl.roleGroups.col.roles", "Roles", null),
        ROLE_GROUPS_COL_ACTIONS("acl.roleGroups.col.actions", "", null),
        GRANTS_SEARCH_FIELD("acl.grants.search.field", "", null),
        GRANTS_SEARCH("acl.grants.search", "", "Search"),
        GRANTS_SUBTITLE("acl.grants.subtitle", "", null),
        GRANTS_TABLE("acl.grants.table", "", null),
        GRANTS_COL_SUBJECT("acl.grants.col.subject", "Subject", null),
        GRANTS_COL_TYPE("acl.grants.col.type", "Grant Type", null),
        GRANTS_COL_GRANTED("acl.grants.col.granted", "Granted", null),
        GRANTS_COL_ACTIONS("acl.grants.col.actions", "", null);

        private final GetNameDescriptionDisplay gndd;

        AclPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Profile page (2026-11-01 conversion): the Name block, the Identifiers and Addresses lists and their dialogs. */
    public enum ProfilePage implements GetNameDescriptionDisplay {
        PAGE("profile", "Profile", "Your account: name, date of birth, identifiers and addresses."),
        NAME_TITLE("profile.name", "Name", null),
        NAME_NOTE("profile.name.note", "How the account is shown; kept in this store under your account and nowhere else.", null),
        FIRST_NAME("profile.firstName", "First name", null),
        FIRST_NAME_FIELD("profile.firstName.field", "", null),
        LAST_NAME("profile.lastName", "Last name", null),
        LAST_NAME_FIELD("profile.lastName.field", "", null),
        DOB("profile.dob", "Date of birth", "Optional, as yyyy-mm-dd."),
        DOB_FIELD("profile.dob.field", "", "Optional, as yyyy-mm-dd."),
        SAVE("profile.save", "Save changes", null),
        STATUS("profile.status", "", null),
        SAVING("profile.status.saving", "Saving…", null),
        SAVED("profile.status.saved", "Saved.", null),
        IDENTIFIERS("profile.identifiers", "Identifiers", "The names you can sign in with: usernames and email addresses. Deleting the one "
                + "you signed in with moves your account to another of them."),
        IDENTIFIERS_ADD("profile.identifiers.add", "+ Add identifier", null),
        ADD_IDENTIFIER_DIALOG("profile.identifiers.add.dialog", "Add identifier", null),
        ADD_IDENTIFIER_KIND("profile.identifiers.add.kind", "Kind", null),
        ADD_IDENTIFIER_VALUE("profile.identifiers.add.value", "Value", null),
        ADD_IDENTIFIER_VALUE_FIELD("profile.identifiers.add.value.field", "", null),
        INVALID_EMAIL_DIALOG("profile.identifiers.add.invalid.dialog", "Invalid email", null),
        DELETE_IDENTIFIER_DIALOG("profile.identifiers.delete.dialog", "Delete identifier", null),
        ADDRESSES("profile.addresses", "Addresses", "Postal addresses kept with your account, for your own records; nothing reads them."),
        ADDRESSES_ADD("profile.addresses.add", "+ Add address", null),
        ADDRESSES_EMPTY("profile.addresses.empty", "No addresses yet", null),
        DELETE_ADDRESS_DIALOG("profile.addresses.delete.dialog", "Delete address", null);

        private final GetNameDescriptionDisplay gndd;

        ProfilePage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The address detail card of the Profile page (2026-11-01 conversion): its fields, note and Save. */
    public enum AddressEditor implements GetNameDescriptionDisplay {
        EDITOR("address", "Address", null),
        NOTE("address.note", "A label or a street is enough to save it.", null),
        LABEL("address.label", "Label", "A name for it: Home, Work…"),
        LABEL_FIELD("address.label.field", "", "A name for it: Home, Work…"),
        STREET("address.street", "Street", null),
        STREET_FIELD("address.street.field", "", null),
        CITY("address.city", "City", null),
        CITY_FIELD("address.city.field", "", null),
        REGION("address.region", "State / region", null),
        REGION_FIELD("address.region.field", "", null),
        POSTAL("address.postal", "Postal code", null),
        POSTAL_FIELD("address.postal.field", "", null),
        COUNTRY("address.country", "Country", null),
        COUNTRY_FIELD("address.country.field", "", null),
        SAVE("address.save", "Save address", null),
        MISSING_DIALOG("address.missing.dialog", "Missing information", null);

        private final GetNameDescriptionDisplay gndd;

        AddressEditor(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The change-password card of the API Keys page (2026-11-01 conversion). */
    public enum PasswordEditor implements GetNameDescriptionDisplay {
        EDITOR("password", "Change password", null),
        NOTE("password.note", "The password you sign in with. The vault password is changed outside the app.", null),
        CURRENT("password.current", "Current password", null),
        CURRENT_FIELD("password.current.field", "", null),
        NEW("password.new", "New password", null),
        NEW_FIELD("password.new.field", "", null),
        CONFIRM("password.confirm", "Confirm new password", "Type the new password again."),
        CONFIRM_FIELD("password.confirm.field", "", "Type the new password again."),
        SUBMIT("password.submit", "Change password", null),
        ERROR_DIALOG("password.error.dialog", "Error", null);

        private final GetNameDescriptionDisplay gndd;

        PasswordEditor(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The API Keys page (2026-11-01 conversion): the credential list, the add dialog and the key editor. */
    public enum ApiKeysPage implements GetNameDescriptionDisplay {
        PAGE("apiKeys", "API Keys", "Your password, and the third-party API keys the assistant borrows; it holds none of its own."),
        PLACEHOLDER("apiKeys.placeholder", "Select a key to edit it, or add one.", null),
        ADD("apiKeys.add", "Add API key", null),
        PASSWORD_SECTION("apiKeys.password", "Password", "The password you sign in with. The vault password is a different one and is not kept here."),
        KEYS_SECTION("apiKeys.keys", "API keys", "Keys of third-party AI providers, kept sealed in this store under your account. "
                + "The assistant's Providers page picks among them; a key is never sent anywhere but to its own provider."),
        KEYS_EMPTY("apiKeys.keys.empty", "No API keys yet", null),
        ADD_DIALOG("apiKeys.add.dialog", "Add API key", null),
        ADD_CREATE("apiKeys.add.create", "Create key", null),
        ADD_CANCEL("apiKeys.add.cancel", "Cancel", null),
        ADD_TITLE("apiKeys.add.title", "Add a third-party API key", null),
        ADD_NOTE("apiKeys.add.note", "The key is sealed in this store under your account and sent only to its own provider.", null),
        SECTION_KEY("apiKeys.section.key", "Key", null),
        SECTION_SCOPE("apiKeys.section.scope", "Scope", null),
        SECTION_ENDPOINT("apiKeys.section.endpoint", "Provider endpoint", null),
        LABEL("apiKeys.label", "Label", null),
        LABEL_EDIT_FIELD("apiKeys.label.edit.field", "", null),
        LABEL_FIELD("apiKeys.label.field", "e.g. Claude prod", null),
        DESCRIPTION("apiKeys.description", "Description", null),
        DESCRIPTION_EDIT_FIELD("apiKeys.description.edit.field", "", null),
        DESCRIPTION_FIELD("apiKeys.description.field", "What this key is for", null),
        KEY("apiKeys.key", "API key", null),
        KEY_FIELD("apiKeys.key.field", "Your API key", null),
        APP_ID("apiKeys.appId", "App ID", null),
        APP_ID_EDIT_FIELD("apiKeys.appId.edit.field", "", null),
        APP_ID_FIELD("apiKeys.appId.field", "e.g. nosneak", null),
        DOMAIN_ID("apiKeys.domainId", "Domain ID", "Both, or neither."),
        DOMAIN_ID_EDIT_FIELD("apiKeys.domainId.edit.field", "", "Both, or neither."),
        DOMAIN_ID_FIELD("apiKeys.domainId.field", "e.g. xlogistx.io", null),
        PROVIDER("apiKeys.provider", "Provider", "Pick one, or type the name of another."),
        PROVIDER_FIELD("apiKeys.provider.field", "Select or type a provider", null),
        BASE_URL("apiKeys.baseUrl", "Base URL", null),
        BASE_URL_EDIT_FIELD("apiKeys.baseUrl.edit.field", "", null),
        BASE_URL_FIELD("apiKeys.baseUrl.field", "e.g. https://api.anthropic.com", null),
        AUTH_SCHEME_FIELD("apiKeys.authScheme.field", "e.g. Bearer Token", null),
        HEADER_NAME_FIELD("apiKeys.headerName.field", "e.g. x-api-key", null),
        GENERATE_LABEL_FIELD("apiKeys.generate.label.field", "e.g Claude prod", null),
        GENERATE_KEY("apiKeys.generate.key", "API Key", null),
        GENERATE_COPY("apiKeys.generate.copy", "", "Copy"),
        GENERATE_REFRESH("apiKeys.generate.refresh", "", "Refresh"),
        COPIED("apiKeys.copied", "", "Copied (cleared from the clipboard after 60 s)"),
        EDITOR("apiKeys.edit", "Edit API key", null),
        EDIT_KEY("apiKeys.edit.key", "API key", "Copy it, or show it; it cannot be edited here. Delete the key and add the new one instead."),
        SAVE("apiKeys.edit.save", "Save", "Save"),
        ROTATE("apiKeys.edit.rotate", "", "Rotate"),
        ROTATE_EXTERNAL("apiKeys.edit.rotate.external", "", "External keys can't be rotated"),
        COPY_KEY("apiKeys.edit.copy", "", "Copy"),
        SHOW_KEY("apiKeys.edit.show", "", "Show"),
        HIDE_KEY("apiKeys.edit.hide", "", "Hide"),
        DELETE("apiKeys.edit.delete", "Delete", "Permanently delete this API key"),
        MISSING_DIALOG("apiKeys.missing.dialog", "Missing information", null),
        ERROR_DIALOG("apiKeys.error.dialog", "Error", null),
        ROTATE_DIALOG("apiKeys.rotate.dialog", "Rotate API key", null),
        DELETE_DIALOG("apiKeys.delete.dialog", "Delete API key", null);

        private final GetNameDescriptionDisplay gndd;

        ApiKeysPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Settings page (2026-11-01 conversion): the Sync, Assistant, Backup and Restore blocks. */
    public enum SettingsPage implements GetNameDescriptionDisplay {
        PAGE("settings", "Settings", "Reference data this installation keeps up to date, the assistant's reply timeout, and the store's backup."),
        SYNC_TITLE("settings.sync", "Sync", null),
        SYNC_NOTE("settings.sync.note", """
                MAC vendors — the Wireshark manufacturer list (wireshark.org, manuf) names the vendor \
                of each host's network adapter in scan reports: the MAC and Vendor columns of the Hosts \
                tab and the Network adapter block of the host detail. It is downloaded once at the \
                first sign-in and kept in this store for every account; the status bar at the bottom \
                of the window shows its state.

                Sync downloads the current list and replaces the stored copy. Wireshark publishes a \
                new one about once a week.""", null),
        SYNC("settings.sync.button", "Sync MAC vendors", null),
        SYNC_STATUS("settings.sync.status", "", null),
        SYNC_DOWNLOADING("settings.sync.status.downloading", "Downloading the vendor list…", null),
        SYNC_LOADING("settings.sync.status.loading", "Loading the vendor list…", null),
        ASSISTANT_TITLE("settings.assistant", "Assistant", null),
        ASSISTANT_NOTE("settings.assistant.note", """
                Reply timeout — how long a request to an AI provider may wait for its answer before \
                the send is given up and reported as failed. 40 seconds is right for a responsive \
                endpoint; stretch it when the one you use is congested and sends time out, lower it \
                to fail faster. It applies to the next request of every provider and is kept for \
                this installation.""", null),
        REPLY_TIMEOUT("settings.assistant.replyTimeout", "", "Seconds a provider may take to answer one request, "
                + io.xlogistx.nosneak.app.ui.utility.AppPrefs.AI_TIMEOUT_MIN + " to " + io.xlogistx.nosneak.app.ui.utility.AppPrefs.AI_TIMEOUT_MAX
                + "; the default is " + io.xlogistx.nosneak.app.ui.utility.AppPrefs.AI_TIMEOUT_DEFAULT + "."),
        REPLY_TIMEOUT_LABEL("settings.assistant.replyTimeout.label", "Reply timeout", null),
        REPLY_TIMEOUT_UNIT("settings.assistant.replyTimeout.unit", "seconds", null),
        BACKUP_TITLE("settings.backup", "Backup", null),
        BACKUP_NOTE("settings.backup.note", """
                Exports every record in this store — accounts and their API keys, scan reports, chats, \
                captures, skills, probes and the MAC vendor list — as one zip archive.

                The archive itself is not encrypted; the sealed values in it (API keys and other \
                secrets) can only be opened again with this installation's vault, so keep the file \
                somewhere you would keep the vault, and keep the vault. Scan reports in it carry \
                your network's layout, so treat it as sensitive.""", null),
        EXPORT("settings.backup.export", "Export backup", null),
        BACKUP_STATUS("settings.backup.status", "", null),
        EXPORTING("settings.backup.status.exporting", "Exporting…", null),
        EXPORTED("settings.backup.status.exported", "Exported", null),
        EXPORT_DIALOG("settings.backup.export.dialog", "Export backup", null),
        BACKUP_ERROR_DIALOG("settings.backup.error.dialog", "Backup", null),
        RESTORE_TITLE("settings.restore", "Restore", null),
        RESTORE_NOTE("settings.restore.note", """
                Loads a backup archive back into this store: accounts and their API keys, scan reports, \
                chats, captures, skills, probes and the MAC vendor list, all under the accounts that \
                owned them. The vault is not touched; sealed values in the archive open only with the \
                vault they were exported under.

                Merge keeps what is already here and adds or overwrites records from the archive. \
                Replace clears the store first, so it ends up holding exactly what the archive holds.

                You are signed out when the restore finishes — the account you are signed in as may \
                have been rewritten or removed by it. Sign in again to carry on.""", null),
        RESTORE_MODE("settings.restore.mode", "", null),
        RESTORE_MODE_MERGE("settings.restore.mode.merge", "Merge into this store", null),
        RESTORE_MODE_REPLACE("settings.restore.mode.replace", "Replace this store", null),
        RESTORE("settings.restore.button", "Restore backup", null),
        RESTORE_STATUS("settings.restore.status", "", null),
        RESTORING("settings.restore.status.restoring", "Restoring…", null),
        RESTORED("settings.restore.status.restored", "Restored", null),
        RESTORE_DIALOG("settings.restore.dialog", "Restore backup", null),
        RESTORE_ERROR_DIALOG("settings.restore.error.dialog", "Restore", null);

        private final GetNameDescriptionDisplay gndd;

        SettingsPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Scan page (2026-11-01): the head under the sidebar's Scan item, the probe chips and their Add probe action, and the page's dialog titles. */
    public enum ScanPage implements GetNameDescriptionDisplay {
        PAGE("scanPage", "", "The scan set-up, its probes and the run's result"),
        SUBTITLE("scanPage.subtitle", "Assess what the hosts on a segment expose. Only ordinary handshakes are sent, from this machine's own address.", null),
        NEW_SCAN("scanPage.newScan", "New scan", "Start over: clear the targets, ports, name, options, probes and the last result"),
        PROBES_EMPTY("scanPage.probes.empty", "none · no probing (tick Service detection for all)", null),
        ADD_PROBE("scanPage.probes.add", "Add probe", null),
        CHIP_MINE("scanPage.probes.chip.mine", "mine", null),
        SESSION_ENDED_DIALOG("scanPage.sessionEnded.dialog", "Scan", null),
        USAGE_DIALOG("scanPage.usage.dialog", "Usage", null),
        SEND_TO_CHAT_DIALOG("scanPage.sendToChat.dialog", "Send to chat", null);

        private final GetNameDescriptionDisplay gndd;

        ScanPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Add probe popup's probe sections (the GROUPS section is {@link ProbeGroupMenu}): a header, an empty text and an All item per section. */
    public enum ProbeMenu implements GetNameDescriptionDisplay {
        SECTION_BUNDLED("probeMenu.bundled", "Bundled probes", null),
        EMPTY_BUNDLED("probeMenu.bundled.empty", "None loaded", null),
        SECTION_MINE("probeMenu.mine", "My probes", null),
        EMPTY_MINE("probeMenu.mine.empty", "No probes yet", null),
        ALL("probeMenu.all", "All", null);

        private final GetNameDescriptionDisplay gndd;

        ProbeMenu(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Probe library page (2026-10-26): head, bar, table, the how-to card with nothing selected and the selected probe's card; the filter segment is {@link ProbeLibraryFilter}, the columns {@link ProbeLibraryColumn}. */
    public enum ProbeLibraryPage implements GetNameDescriptionDisplay {
        PAGE("probeLibrary", "Probe library", "Every probe a scan can run: the bundled set and your own"),
        TITLE("probeLibrary.title", "Probe library", null),
        SUBTITLE("probeLibrary.subtitle", "The service probes a scan can run: the bundled set and your own. Select one to read it.", null),
        WRITE_WITH_ASSISTANT("probeLibrary.writeWithAssistant", "Write with the assistant", "Hand the assistant the probe definition and ask it for a probe"),
        NEW_PROBE("probeLibrary.newProbe", "New probe", null),
        SEARCH("probeLibrary.search", "Search name, service, port", null),
        COUNT("probeLibrary.count", "", null),
        TABLE("probeLibrary.table", "", null),
        DEFINITION("probeLibrary.definition", "Probe definition", "The contract a probe file follows, with examples"),
        HOWTO_TITLE("probeLibrary.howto", "How to add a probe", null),
        HOWTO_TEXT("probeLibrary.howto.text", "A probe is one JSON file: a small state machine that connects, sends the minimum the protocol needs, matches the reply and records the service. Select a probe on the left to read it. Three ways to add one:", null),
        HOWTO_COPY("probeLibrary.howto.copy", "Copy a bundled probe", "Pick one on the left, then Copy to my probes and change what you need."),
        HOWTO_ASK("probeLibrary.howto.ask", "Write with the assistant", "It gets the probe definition and returns the JSON; one click on the reply saves it here."),
        HOWTO_NEW("probeLibrary.howto.new", "New probe", "Start from an empty editor, with the Probe definition one click away."),
        PROBE_TITLE("probeLibrary.probe.title", "", null),
        COPY("probeLibrary.probe.copy", "Copy to my probes", "Open the editor with this probe's JSON as your draft"),
        EDIT("probeLibrary.probe.edit", "Edit", null),
        DELETE("probeLibrary.probe.delete", "Delete", null),
        DELETE_DIALOG("probeLibrary.probe.delete.dialog", "Delete probe", null),
        SOURCE("probeLibrary.probe.source", "", null),
        FACT_DESCRIPTION("probeLibrary.probe.fact.description", "Description", null),
        FACT_SERVICE("probeLibrary.probe.fact.service", "Service", null),
        FACT_TRANSPORT("probeLibrary.probe.fact.transport", "Transport", null),
        FACT_PORTS("probeLibrary.probe.fact.ports", "Ports", null),
        FACT_PRIORITY("probeLibrary.probe.fact.priority", "Priority", null),
        FACT_PORT_SCOPED("probeLibrary.probe.fact.portScoped", "Port-scoped", null),
        FACT_WATCHDOG("probeLibrary.probe.fact.watchdog", "Watchdog", null),
        FACT_STATES("probeLibrary.probe.fact.states", "States", null),
        FACT_SOURCE("probeLibrary.probe.fact.source", "Source", null),
        SOURCE_MINE("probeLibrary.probe.source.mine", "mine, stored under your account", null),
        SOURCE_BUNDLED("probeLibrary.probe.source.bundled", "bundled with no-sneak", null),
        BADGE_BUNDLED("probeLibrary.badge.bundled", "bundled", null),
        BADGE_MINE("probeLibrary.badge.mine", "mine", null);

        private final GetNameDescriptionDisplay gndd;

        ProbeLibraryPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Probe definition card: PROBE-DEFINITION.md rendered in the app, behind the library bar's Probe definition button. */
    public enum ProbeDefinitionPage implements GetNameDescriptionDisplay {
        PAGE("probeDefinition", "Probe definition", null),
        SUBTITLE("probeDefinition.subtitle", "no-sneak-core/PROBE-DEFINITION.md: what a probe.json may contain, every action, the validation rules and worked examples.", null);

        private final GetNameDescriptionDisplay gndd;

        ProbeDefinitionPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Write a probe with the assistant dialog (2026-10-26): what to detect and where, then the Chat page opens with the request typed. */
    public enum AskProbe implements GetNameDescriptionDisplay {
        DIALOG("askProbe.dialog", "Write a probe with the assistant", null),
        SERVICE("askProbe.service", "Service", null),
        SERVICE_FIELD("askProbe.service.field", "", null),
        PORT("askProbe.port", "Port", null),
        PORT_FIELD("askProbe.port.field", "", null),
        HINT("askProbe.hint", "The assistant gets PROBE-DEFINITION.md with the request and answers with one JSON object; the reply carries a Save as probe button.", null),
        FAILED_DIALOG("askProbe.failed.dialog", "Write with the assistant", null);

        private final GetNameDescriptionDisplay gndd;

        AskProbe(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The Scan history page (2026-10-24): head, search and count, the row actions, and the dialog titles; the columns are {@link ScanHistoryColumn}. */
    public enum ScanHistoryPage implements GetNameDescriptionDisplay {
        PAGE("scanHistory", "Scan history", "Every completed scan you ran, kept under your account"),
        TITLE("scanHistory.title", "Scan history", null),
        SUBTITLE("scanHistory.subtitle", "Every completed scan you ran, kept in this store under your account only. Stopped scans are not saved.", null),
        NEW_SCAN("scanHistory.newScan", "New scan", null),
        SEARCH("scanHistory.search", "Search by name, target or command", null),
        COUNT("scanHistory.count", "", null),
        COUNT_EMPTY("scanHistory.count.empty", "No scans yet", null),
        TABLE("scanHistory.table", "", null),
        VIEW("scanHistory.view", "View", null),
        AGAIN("scanHistory.again", "Scan again", "Load this scan's command, probes and name into New scan"),
        AGAIN_DIALOG("scanHistory.again.dialog", "Scan again", null),
        COPY_COMMAND("scanHistory.copyCommand", "Copy command", null),
        COPY_RESULT("scanHistory.copyResult", "Copy result", null),
        SEND("scanHistory.send", "Send to assistant", null),
        DELETE("scanHistory.delete", "Delete", null),
        DELETE_DIALOG("scanHistory.delete.dialog", "Delete scan", null),
        DELETE_ALL("scanHistory.deleteAll", "Delete all", "Delete every scan in your history"),
        DELETE_ALL_DIALOG("scanHistory.deleteAll.dialog", "Delete all scans", null),
        NOT_FOUND_DIALOG("scanHistory.notFound.dialog", "Not found", null);

        private final GetNameDescriptionDisplay gndd;

        ScanHistoryPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The columns of the Scan history table, in order; {@code ScanPanel.HistoryModel} reads its headers here. */
    public enum ScanHistoryColumn implements GetNameDescriptionDisplay {
        SCAN("scanHistory.col.scan", "Scan", "The scan's name, or its targets"),
        COMMAND("scanHistory.col.command", "Command", "The command the scan ran with"),
        WHEN("scanHistory.col.when", "When", "When the scan was run"),
        HOSTS_UP("scanHistory.col.hostsUp", "Hosts up", "Hosts that answered"),
        OPEN_PORTS("scanHistory.col.openPorts", "Open ports", "Open ports found across the hosts");

        private final GetNameDescriptionDisplay gndd;

        ScanHistoryColumn(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The card that shows a stored report opened from the history, with its way back. */
    public enum ViewScanPage implements GetNameDescriptionDisplay {
        PAGE("viewScan", "", "A stored report, in the same tables as a fresh run"),
        BACK("viewScan.back", "Back to history", null);

        private final GetNameDescriptionDisplay gndd;

        ViewScanPage(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    /** The probe editor card (2026-10-26): the JSON draft, Check, Save, the name read from the JSON, and the help line. */
    public enum ProbeEditor implements GetNameDescriptionDisplay {
        PAGE("probeEditor", "Probe editor", null),
        BACK("probeEditor.back", "", "Back to the library"),
        TITLE("probeEditor.title", "", null),
        TITLE_NEW("probeEditor.title.new", "New probe", null),
        TITLE_EDIT("probeEditor.title.edit", "Edit probe", null),
        TITLE_COPY("probeEditor.title.copy", "Copy of", null),
        HELP_ONE("probeEditor.help.one", "One JSON object. See the", null),
        HELP_DEFINITION("probeEditor.help.definition", "Probe definition", null),
        HELP_OR("probeEditor.help.or", ", or let the", null),
        HELP_ASK("probeEditor.help.ask", "assistant write it", null),
        SHADOW("probeEditor.shadow", "A stored probe with a bundled probe's name replaces that probe in your scans (the report says so); rename it in the JSON to keep both.", null),
        SAVE("probeEditor.save", "Save", null),
        CHECK("probeEditor.check", "Check", "Validate the draft the way the engine will"),
        NAME("probeEditor.name", "", null),
        NAME_PENDING("probeEditor.name.pending", "Name: taken from the JSON once it is valid", null),
        NAME_PREFIX("probeEditor.name.prefix", "Name:", null),
        SOURCE("probeEditor.source", "", null),
        INVALID_DIALOG("probeEditor.invalid.dialog", "Not a valid probe", null),
        SAVED_DIALOG("probeEditor.saved.dialog", "Probe", null);

        private final GetNameDescriptionDisplay gndd;

        ProbeEditor(String name, String displayName, String description) {
            gndd = new GetNameDescriptionDisplayImpl(name, description, displayName);
        }

        @Override
        public String getName() {
            return gndd.getName();
        }

        @Override
        public String getDisplayName() {
            return gndd.getDisplayName();
        }

        @Override
        public String getDescription() {
            return gndd.getDescription();
        }
    }

    // ---- enums are added above this line; one per panel or feature ----
}
