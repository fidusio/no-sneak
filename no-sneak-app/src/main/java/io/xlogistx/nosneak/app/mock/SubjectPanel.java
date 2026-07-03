package io.xlogistx.nosneak.app.mock;

import io.xlogistx.nosneak.app.mock.utility.*;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.PrincipalIdentifier;

import javax.swing.*;
import java.awt.*;
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

    // Data-driven sections (refreshed on auth) + credential detail switching
    private ListSection identifiers;
    private ListSection credentials;
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
            credentials.refresh();
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
                new JLabel("Profile"),
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
        String error = ctx.session().addIdentifier(id.trim());
        if (error != null) {
            JOptionPane.showMessageDialog(this, error, "Error", JOptionPane.ERROR_MESSAGE);
        }
        identifiers.refresh();
    }

    private void onRemoveIdentifier(PrincipalIdentifier p) {

        String error = ctx.session().removeIdentifier(p);
        if (error != null) {
            JOptionPane.showMessageDialog(this, error, "Error", JOptionPane.ERROR_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, "Successfully removed: " + p.getPrincipalID());
        }

        identifiers.refresh();
    }

    // ---- Login credentials (+ change password) ----

    private JPanel buildCredentials() {
        credentialCards.add(buildCredentialList(), "list");
        credentialCards.add(buildChangePassword(), "changePassword");
        credentialCards.show("list");

        JPanel p = new JPanel(new BorderLayout());
        p.add(credentialCards.view(), BorderLayout.CENTER);
        return p;
    }

    private JPanel buildCredentialList() {
        credentials = new ListSection("Login credentials", "+ Add login method",
                this::addCredentialPage,
                this::credentialEntries);

        JPanel p = new JPanel(new BorderLayout());
        p.add(credentials, BorderLayout.CENTER);
        return p;
    }

    private void addCredentialPage() {
        String[] options = {"API Key"};
        int choice = JOptionPane.showOptionDialog(
                this,
                "Choose a login method to add",
                "Add Login Method",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                options[0]
        );

        if (choice == 0) {
            String key = ctx.session().createAPIKey();
            JOptionPane.showMessageDialog(this, "Your API Key is " + key + " dont forget it!");
        }

    }

    private List<ListSection.Entry> credentialEntries() {
        List<ListSection.Entry> out = new ArrayList<>();
        for (CredentialInfo ci : ctx.session().getAllCredentialForLoggedInUser()) {
            if (ci.getCredentialType() == CredentialInfo.Type.PASSWORD) {
                out.add(new ListSection.Entry("Password",
                        () -> credentialCards.show("changePassword"), null));
            } else {
                out.add(new ListSection.Entry(ci.getCredentialType().name() + " — not editable", null, null));
            }
        }
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
                    credentials.refresh();

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
        ctx.session().saveProfile(fields);
        JOptionPane.showMessageDialog(this, "Profile saved.");

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
