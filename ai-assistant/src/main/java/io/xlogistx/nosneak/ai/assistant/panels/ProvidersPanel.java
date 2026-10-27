package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.api.ai.AIAPIBuilder;
import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.AICredentialSource;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.AIAPIProvider;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.assistant.AssistantPanel;
import io.xlogistx.nosneak.ai.model.AIProviderConfig;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.security.APIKey;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.fillModels;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.timestamp;

/**
 * The Providers page (re-laid out 2026-10-26 in the house list look, after Chat History, Capture
 * and Skills): a {@link PagePanel} head with the one primary action (Add provider), a toolbar
 * (search, count, Edit / Remove on the selected row) and a styled table on
 * {@link ProvidersTableModel}, by name; double-click edits. The other three cards are pages of
 * their own: the key picker (a table on {@link ProviderKeysTableModel}, Back / New key / Use this
 * key), the new-key form and the provider form (primary Save beside Cancel).
 */
public class ProvidersPanel extends JPanel {

    private final AssistantContext ctx;

    private Runnable onProvidersChanged;

    public ProvidersPanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());
        add(buildProviderCardsPanel());
    }

    public void setOnProvidersChanged(Runnable onProvidersChanged) {
        this.onProvidersChanged = onProvidersChanged;
    }

    private static final String[] PROVIDER_DISPLAY = {"OpenAI", "Anthropic (Claude)", "Google (Gemini)", "Grok (xAI)"};
    private static final String[] PROVIDER_CANONICAL = {"openai", "anthropic", "gemini", "grok"};

    private final CardStack providerCards = new CardStack();

    private final ProvidersTableModel providersModel = new ProvidersTableModel();
    private final JTable providersTable = new JTable(providersModel);
    private final TableRowSorter<ProvidersTableModel> providersSorter = new TableRowSorter<>(providersModel);
    private final JLabel providersCount = new JLabel();

    private final ProviderKeysTableModel keysModel = new ProviderKeysTableModel();
    private final JTable keysTable = new JTable(keysModel);
    private final JLabel keysCount = new JLabel();

    private final JPanel formHost = new JPanel(new BorderLayout());
    private JPanel providerForm;
    private final JTextField providerFormLabel = PanelBuilder.textField("e.g. Claude prod");
    private final JComboBox<String> providerFormType = new JComboBox<>(PROVIDER_DISPLAY);
    private final JTextField providerFormBaseURL =
            PanelBuilder.textField("Optional — provider default when empty");
    private final JComboBox<String> providerFormModel = new JComboBox<>();
    private final JLabel providerFormModelLabel = new JLabel("Default model");
    private final JLabel providerFormKey = new JLabel();
    private final JButton providerFormSave = UITokens.primary(new JButton("Save", new IconUtil.SaveIcon(16, Color.WHITE)));
    private AIProviderConfig editingConfig;
    private APIKey<String> editingKey;

    /**
     * Bumped on every {@link #reloadProviders()}; a pass whose number is stale by the time its
     * worker finishes applies nothing, so two overlapping reloads (startup, then a login that
     * fires from the login worker) cannot interleave their results or each other's issues.
     */
    private int reloadGeneration;

    /**
     * Four cards, each a page: {@code list} (the table), {@code add} (the key picker),
     * {@code create} (the new-key form) and {@code form} (the provider form, re-framed with its
     * title on every open). Every {@code providerCards.show("list")} after a save, a remove or a
     * reset lands on the table.
     */
    public JComponent buildProviderCardsPanel() {
        providerCards.add(buildProviderPanel(), "list");
        providerCards.add(buildAddProvider(), "add");
        providerCards.add(buildCreateProviderKey(), "create");
        providerForm = buildProviderForm();
        providerCards.add(formHost, "form");
        providerCards.show("list");
        return providerCards.view();
    }

    public JPanel buildProviderPanel() {
        PagePanel page = new PagePanel(AssistantPanel.Page.PROVIDERS.getDisplayName(),
                "Keys come from your NoSneak credentials. Adding one here lets the assistant use it and discover its models.");
        JButton add = UITokens.primary(new JButton("Add provider", IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)));
        add.addActionListener(_ -> onAddProvider());
        page.action(add);

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[260!][]push[][]"));
        bar.setOpaque(false);
        JTextField search = new JTextField();
        search.putClientProperty("JTextField.placeholderText", "Search by label, type, endpoint or model");
        search.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(14));
        bar.add(search, "growx");
        providersCount.setForeground(UITokens.muted());
        providersCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(providersCount);
        JButton edit = toolButton("Edit", new IconUtil.EditIcon(16));
        JButton remove = toolButton("Remove", new IconUtil.DeleteIcon(16));
        remove.setToolTipText("Remove the provider; the key stays in your NoSneak credentials");
        remove.setForeground(UITokens.danger());
        bar.add(edit);
        bar.add(remove);
        page.row(bar);

        Tables.style(providersTable);
        Tables.width(providersTable, ProvidersTableModel.COL_NAME, 200);
        Tables.width(providersTable, ProvidersTableModel.COL_TYPE, 100);
        Tables.width(providersTable, ProvidersTableModel.COL_ENDPOINT, 260);
        Tables.width(providersTable, ProvidersTableModel.COL_MODEL, 180);
        Tables.width(providersTable, ProvidersTableModel.COL_MODELS, 70);
        Tables.width(providersTable, ProvidersTableModel.COL_SYNCED, 140);
        providersTable.getColumnModel().getColumn(ProvidersTableModel.COL_TYPE).setCellRenderer(new MutedRenderer(false));
        providersTable.getColumnModel().getColumn(ProvidersTableModel.COL_ENDPOINT).setCellRenderer(new MutedRenderer(false));
        providersTable.getColumnModel().getColumn(ProvidersTableModel.COL_SYNCED).setCellRenderer(new MutedRenderer(true));
        providersTable.setRowSorter(providersSorter);
        providersSorter.setSortKeys(List.of(new RowSorter.SortKey(ProvidersTableModel.COL_NAME, SortOrder.ASCENDING)));
        providersTable.getSelectionModel().addListSelectionListener(_ -> {
            boolean one = providersTable.getSelectedRowCount() == 1;
            edit.setEnabled(one);
            remove.setEnabled(one);
        });
        providersTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) onEditProvider(selectedProvider());
            }
        });
        edit.addActionListener(_ -> onEditProvider(selectedProvider()));
        remove.addActionListener(_ -> onRemoveProvider(selectedProvider()));
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                filter();
            }

            public void removeUpdate(DocumentEvent e) {
                filter();
            }

            public void changedUpdate(DocumentEvent e) {
                filter();
            }

            private void filter() {
                String q = search.getText().trim();
                providersSorter.setRowFilter(q.isEmpty() ? null : RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
                updateProvidersCount();
            }
        });
        page.card(tableCard(providersTable));
        updateProvidersCount();
        return page;
    }

    private static JButton toolButton(String text, Icon icon) {
        JButton b = new JButton(text, icon);
        b.putClientProperty("JButton.buttonType", "toolBarButton");
        b.setEnabled(false);
        return b;
    }

    private static JScrollPane tableCard(JTable table) {
        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(UITokens.surface());
        return scroll;
    }

    /** The type / endpoint columns plain, or a {@code yyyy-MM-dd HH:mm} stamp ({@code never synced} when unset); muted. */
    private static final class MutedRenderer extends DefaultTableCellRenderer {
        private final boolean stamp;

        MutedRenderer(boolean stamp) {
            this.stamp = stamp;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (stamp) setText(value instanceof Long l ? timestamp(l) : "never synced");
            if (!isSelected) setForeground(UITokens.muted());
            return this;
        }
    }

    private AIProvider selectedProvider() {
        int row = providersTable.getSelectedRow();
        return row < 0 ? null : providersModel.rowAt(providersTable.convertRowIndexToModel(row)).provider();
    }

    private void updateProvidersCount() {
        int shown = providersTable.getRowCount();
        int all = providersModel.getRowCount();
        providersCount.setText(all == 0 ? "No providers yet" : shown == all ? all + (all == 1 ? " provider" : " providers") : shown + " of " + all + " providers");
    }

    /** The key picker page: every credential the source offers, Back / New key in the head, Use this key on the row. */
    public JPanel buildAddProvider() {
        PagePanel page = new PagePanel("Add a provider",
                "Pick a credential from your NoSneak key store, or add a brand-new key. One key can back several providers.");
        JButton back = new JButton("Back", new IconUtil.BackIcon(16));
        back.addActionListener(_ -> providerCards.show("list"));
        JButton newKey = UITokens.primary(new JButton("New key", IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)));
        newKey.addActionListener(_ -> providerCards.show("create"));
        JPanel actions = new JPanel(new MigLayout("insets 0, gapx 8"));
        actions.setOpaque(false);
        actions.add(back);
        actions.add(newKey);
        page.action(actions);

        JPanel bar = new JPanel(new MigLayout("insets 0, gapx 8", "[]push[]"));
        bar.setOpaque(false);
        keysCount.setForeground(UITokens.muted());
        keysCount.setFont(UITokens.font(Font.PLAIN, -1f));
        bar.add(keysCount);
        JButton use = toolButton("Use this key", new IconUtil.NextIcon(16));
        bar.add(use);
        page.row(bar);

        Tables.style(keysTable);
        Tables.width(keysTable, ProviderKeysTableModel.COL_NAME, 240);
        Tables.width(keysTable, ProviderKeysTableModel.COL_PROVIDER, 120);
        Tables.width(keysTable, ProviderKeysTableModel.COL_ENDPOINT, 300);
        Tables.width(keysTable, ProviderKeysTableModel.COL_USED, 90);
        keysTable.getColumnModel().getColumn(ProviderKeysTableModel.COL_PROVIDER).setCellRenderer(new MutedRenderer(false));
        keysTable.getColumnModel().getColumn(ProviderKeysTableModel.COL_ENDPOINT).setCellRenderer(new MutedRenderer(false));
        keysTable.getSelectionModel().addListSelectionListener(_ -> use.setEnabled(keysTable.getSelectedRowCount() == 1));
        keysTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) onSelectAddKey(selectedKey());
            }
        });
        use.addActionListener(_ -> onSelectAddKey(selectedKey()));
        page.card(tableCard(keysTable));
        return page;
    }

    private APIKey<String> selectedKey() {
        int row = keysTable.getSelectedRow();
        return row < 0 ? null : keysModel.rowAt(keysTable.convertRowIndexToModel(row)).key();
    }

    /** Re-reads the credentials into the picker; the used-by count walks the registrar, once per row. */
    private void refreshKeys() {
        List<ProviderKeysTableModel.Row> rows = new ArrayList<>();
        for (APIKey<String> key : ctx.getCredentials().APIKeys()) {
            String provider = providerOf(key);
            rows.add(ProviderKeysTableModel.row(key, key.getName(),
                    AIAPIProvider.resolveType(provider) != null ? provider : null,
                    baseUrlOf(key), providersUsing(keyIdentity(key))));
        }
        keysModel.setRows(rows);
        int n = rows.size();
        keysCount.setText(n == 0 ? "No keys yet" : n + (n == 1 ? " key" : " keys"));
    }

    /** A form for a page card: label / field rows, then the primary action beside Cancel; the caller adds it with {@code page.card(...)}. */
    private static JPanel formCard(JComponent[][] rows, JButton primary, JButton cancel) {
        JPanel form = new JPanel(new MigLayout("insets 20, wrap 2, gapx 16, gapy 10, hidemode 3", "[right][360!]"));
        form.setOpaque(false);
        for (JComponent[] row : rows) {
            form.add(row[0]);
            form.add(row[1], "growx");
        }
        JPanel actions = new JPanel(new MigLayout("insets 0, gapx 8"));
        actions.setOpaque(false);
        actions.add(primary);
        actions.add(cancel);
        form.add(actions, "skip 1, gaptop 8");
        JPanel top = new JPanel(new BorderLayout());
        top.setOpaque(false);
        top.add(form, BorderLayout.NORTH);
        return top;
    }

    public JPanel buildCreateProviderKey() {
        JTextField keyLabel = PanelBuilder.textField("e.g. Claude prod");
        JComboBox<String> provider = new JComboBox<>(PROVIDER_DISPLAY);
        JPasswordField secret = new JPasswordField(28);
        secret.putClientProperty("JTextField.placeholderText", "Your API key");
        JTextField baseURL = PanelBuilder.textField("Optional — provider default when empty");
        JButton create = UITokens.primary(new JButton("Add to assistant", IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 14, Color.WHITE)));

        create.addActionListener(_ -> {
            String name = keyLabel.getText().trim();
            String rawKey = new String(secret.getPassword()).trim();
            if (name.isEmpty() || rawKey.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Enter a label and the API key.",
                        "Missing information", JOptionPane.WARNING_MESSAGE);
                return;
            }
            String canonical = PROVIDER_CANONICAL[provider.getSelectedIndex()];
            String url = baseURL.getText().trim();

            BackgroundTask.run(this, create,
                    () -> ctx.getCredentials().addAPIKey(name, "", canonical, url, "", "", rawKey),
                    key -> {
                        keyLabel.setText("");
                        secret.setText("");
                        baseURL.setText("");
                        provider.setSelectedIndex(0);
                        showProviderForm(null, key);
                    });
        });
        JButton cancel = new JButton("Cancel");
        cancel.addActionListener(_ -> providerCards.show("add"));

        PagePanel page = new PagePanel("New provider key",
                "A key NoSneak does not have yet. It becomes an ordinary credential of yours, visible on the API Keys page.");
        page.card(formCard(new JComponent[][]{
                {new JLabel("Label*"), keyLabel},
                {new JLabel("Provider*"), provider},
                {new JLabel("API key*"), PanelBuilder.passwordField(secret)},
                {new JLabel("Base URL"), baseURL}}, create, cancel));
        return page;
    }

    /**
     * The add/edit form for one provider. A key may back several of these, so everything the
     * assistant routes on lives here rather than on the credential. The form is built once and
     * framed in a titled page on every open ({@link #showProviderForm}).
     */
    public JPanel buildProviderForm() {
        providerFormModel.setEditable(true);
        providerFormSave.addActionListener(_ -> onSaveProviderConfig());
        JButton cancel = new JButton("Cancel");
        cancel.addActionListener(_ -> {
            editingConfig = null;
            editingKey = null;
            providerCards.show("list");
        });
        providerFormKey.setForeground(UITokens.muted());
        return formCard(new JComponent[][]{
                {new JLabel("Key"), providerFormKey},
                {new JLabel("Label*"), providerFormLabel},
                {new JLabel("Provider*"), providerFormType},
                {new JLabel("Base URL"), providerFormBaseURL},
                // hidden on the add path: discovery has not run yet, so the combo would be empty
                {providerFormModelLabel, providerFormModel}}, providerFormSave, cancel);
    }

    /**
     * Opens the form on an existing config, or on a new one seeded from the key's own metadata.
     */
    private void showProviderForm(AIProviderConfig config, APIKey<String> key) {
        if (key == null) return;
        editingConfig = config;
        editingKey = key;

        String type = (config != null) ? config.getProviderType() : providerOf(key);
        String baseURL = (config != null) ? config.getBaseURL() : baseUrlOf(key);

        providerFormKey.setText(key.getName() != null ? key.getName() : "");
        providerFormLabel.setText(config != null && config.getName() != null
                ? config.getName() : (key.getName() != null ? key.getName() : ""));
        providerFormType.setSelectedIndex(providerIndex(type));
        providerFormBaseURL.setText(baseURL != null ? baseURL : "");
        providerFormSave.setText(config != null ? "Save" : "Add to assistant");

        providerFormModel.removeAllItems();
        providerFormModelLabel.setVisible(config != null);
        providerFormModel.setVisible(config != null);
        if (config != null) {
            fillModels(ctx, providerFormModel, config.getGUID(), false);
            providerFormModel.setSelectedItem(config.getDefaultModel());
        } else {
            providerFormModel.setSelectedItem("");
        }

        PagePanel page = config != null
                ? new PagePanel("Edit provider", "Change what the assistant calls it, which service it talks to, its endpoint and the model it starts with.")
                : new PagePanel("Add provider", "Name it and confirm the service and endpoint; the default model can be picked once its models are discovered.");
        page.card(providerForm);
        formHost.removeAll();
        formHost.add(page, BorderLayout.CENTER);
        formHost.revalidate();
        formHost.repaint();
        providerCards.show("form");
    }

    private void onSaveProviderConfig() {
        String label = providerFormLabel.getText().trim();
        if (label.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Give the provider a label.",
                    "Missing information", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (editingKey == null) return;

        AIProviderConfig config = (editingConfig != null) ? editingConfig : new AIProviderConfig();
        config.setName(label);
        config.setKeyGUID(keyIdentity(editingKey));
        config.setProviderType(PROVIDER_CANONICAL[providerFormType.getSelectedIndex()]);
        config.setBaseURL(providerFormBaseURL.getText().trim());
        Object model = providerFormModel.getSelectedItem();
        config.setDefaultModel(model != null ? model.toString().trim() : "");
        config.setEnabled(true);

        final APIKey<String> key = editingKey;
        BackgroundTask.run(this, providerFormSave,
                () -> {
                    AIProviderConfig saved = ctx.saveProviderConfig(config);
                    ctx.getCredentials().setEnabled(key, true);
                    AIAPIProvider p = AIAPIProvider.create(saved, key);
                    if (p != null) {
                        try {
                            p.getModelCatalog().refresh();
                        } catch (Exception ignore) {
                        }
                    }
                    return p;
                },
                p -> {
                    if (p != null) ctx.getProviders().put(p.getID(), p);
                    editingConfig = null;
                    editingKey = null;
                    refreshProviderViews();
                    providerCards.show("list");
                });
    }

    private void onSelectAddKey(APIKey<String> key) {
        if (key == null) return;
        if (keyIdentity(key) == null) {
            JOptionPane.showMessageDialog(this,
                    "This key has not been saved yet, so a provider cannot be attached to it.",
                    "Add provider", JOptionPane.WARNING_MESSAGE);
            return;
        }
        showProviderForm(null, key);
    }

    private void onEditProvider(AIProvider provider) {
        if (!(provider instanceof AIAPIProvider p) || p.getAPIKey() == null) return;
        showProviderForm(p.getConfig(), p.getAPIKey());
    }

    private void onAddProvider() {
        refreshKeys();
        providerCards.show("add");
    }

    private void onRemoveProvider(AIProvider provider) {
        if (!(provider instanceof AIAPIProvider p)) return;
        int res = JOptionPane.showConfirmDialog(this,
                "Remove provider '" + p.getName() + "'? The key stays in your NoSneak credentials.",
                "Remove provider", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;

        AIProviderConfig config = p.getConfig();
        BackgroundTask.run(this, null,
                () -> {
                    ctx.deleteProviderConfig(config);
                    // assistant-enabled is derived now: the key stays linked only while some
                    // config still borrows it, so a stale flag can't resurrect it at next login.
                    APIKey<String> key = p.getAPIKey();
                    if (key != null && ctx.configsUsing(keyIdentity(key)) == 0)
                        ctx.getCredentials().setEnabled(key, false);
                    return null;
                },
                _ -> {
                    ctx.getProviders().unregister(p.getID());
                    refreshProviderViews();
                });
    }

    /** One reload pass's outcome: the providers it built and the problems it met, together. */
    private record ReloadPass(int generation, List<AIProvider> built, List<String> issues) {}

    /**
     * Rebuilds the provider set from the stored configs. Safe to call from any thread — the
     * login path fires it from the login worker — and safe to call while a previous pass is still
     * blocked in a catalog refresh: each pass collects its own issue list and carries its own
     * generation number, and only the newest pass is applied.
     */
    public void reloadProviders() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::reloadProviders);
            return;
        }
        final int generation = ++reloadGeneration;
        BackgroundTask.run(this, null, () -> {
            List<String> issues = new ArrayList<>();
            List<AIProviderConfig> configs = ctx.getAllProviderConfigs();
            if (configs.isEmpty()) configs = adoptEnabledKeys();

            Map<String, APIKey<String>> keysByGUID = new HashMap<>();
            for (APIKey<String> k : ctx.getCredentials().APIKeys()) {
                String guid = keyIdentity(k);
                if (guid != null) keysByGUID.put(guid, k);
            }

            List<AIProvider> built = new ArrayList<>();
            for (AIProviderConfig cfg : configs) {
                if (!cfg.isEnabled()) continue;
                APIKey<String> key = keysByGUID.get(cfg.getKeyGUID());
                if (key == null) {
                    issues.add(cfg.getName() + ": its credential is no longer available");
                    continue;
                }
                AIAPIProvider p = AIAPIProvider.create(cfg, key);
                if (p == null) {
                    issues.add(cfg.getName() + ": unrecognized provider type '"
                            + cfg.getProviderType() + "'");
                    continue;
                }
                try {
                    p.getModelCatalog().refresh();
                } catch (Exception e) {
                    issues.add(cfg.getName() + ": " + e.getMessage());
                }
                built.add(p);
            }
            return new ReloadPass(generation, built, issues);
        }, pass -> {
            if (pass.generation() != reloadGeneration) {
                return; // a newer reload has started; its result is the one that counts
            }
            ctx.clearProviders();
            for (AIProvider p : pass.built()) ctx.getProviders().put(p.getID(), p);
            refreshProviderViews();
            if (!pass.issues().isEmpty()) {
                JOptionPane.showMessageDialog(this, String.join("\n", pass.issues()),
                        "Provider Error", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    /**
     * One-time upgrade: subjects who linked keys before providers became their own record have
     * assistant-enabled credentials and no configs. Give each one a config so their providers
     * survive the change. Runs only while the subject has none.
     */
    private List<AIProviderConfig> adoptEnabledKeys() {
        List<AIProviderConfig> out = new ArrayList<>();
        for (APIKey<String> key : ctx.getCredentials().enabledAPIKeys()) {
            String type = providerOf(key);
            String keyGUID = keyIdentity(key);
            if (keyGUID == null || AIAPIProvider.resolveType(type) == null) continue;
            AIProviderConfig cfg = new AIProviderConfig(key.getName(), keyGUID, type);
            cfg.setBaseURL(baseUrlOf(key));
            out.add(ctx.saveProviderConfig(cfg));
        }
        return out;
    }

    public void clearProviders() {
        ctx.clearProviders();
        refreshProviderViews();
    }

    /** Re-reads the registrar into the table (EDT-safe) and keeps the selected row by provider ID. */
    public void refreshList() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshList);
            return;
        }
        AIProvider keep = selectedProvider();
        List<ProvidersTableModel.Row> rows = new ArrayList<>();
        for (AIProvider p : ctx.getProvidersList()) rows.add(ProvidersTableModel.rowOf(p));
        providersModel.setRows(rows);
        int model = keep == null ? -1 : providersModel.indexOf(keep.getID());
        if (model >= 0) {
            int view = providersTable.convertRowIndexToView(model);
            providersTable.setRowSelectionInterval(view, view);
        }
        updateProvidersCount();
    }

    public void reset() {
        providerCards.show("list");
        editingConfig = null;
        editingKey = null;
    }

    /**
     * The key picker is not refreshed here — its rows query the credential store, and
     * {@link #onAddProvider()} already refreshes them every time its page opens.
     */
    private void refreshProviderViews() {
        refreshList();
        if (onProvidersChanged != null) onProvidersChanged.run();
    }

    private static int providerIndex(String canonical) {
        AIAPIBuilder.AIAPIType type = AIAPIProvider.resolveType(canonical);
        if (type != null) {
            for (int i = 0; i < PROVIDER_CANONICAL.length; i++) {
                if (type == AIAPIProvider.resolveType(PROVIDER_CANONICAL[i])) return i;
            }
        }
        return 0;
    }

    private static String keyIdentity(APIKey<String> key) {
        return AICredentialSource.guidOf(key);
    }

    /**
     * Counts off the registrar rather than the store: the registered providers are exactly the
     * configs in play, and this runs once per key when the picker's rows are built.
     *
     * @return how many live providers borrow this credential
     */
    private int providersUsing(String keyGUID) {
        if (keyGUID == null) return 0;
        int count = 0;
        for (AIProvider p : ctx.getProvidersList()) {
            if (p instanceof AIAPIProvider api && keyGUID.equals(api.getConfig().getKeyGUID())) count++;
        }
        return count;
    }

    private String providerOf(APIKey<String> key) {
        return keyProperty(key, "provider");
    }

    private String baseUrlOf(APIKey<String> key) {
        return keyProperty(key, "base-url");
    }

    private String keyProperty(APIKey<String> key, String name) {
        Object v = (key != null && key.getProperties() != null) ? key.getProperties().getValue(name) : null;
        return v == null ? null : v.toString();
    }
}
